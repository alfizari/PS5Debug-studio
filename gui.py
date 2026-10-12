"""PS5 cheat & debug toolkit for ps5debug-NG (stdlib Tk). Run: python gui.py"""

from __future__ import annotations

import collections
import json
import re
import struct
import sys
import threading
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path

from app_paths import APP_DIR
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import asmgen  # noqa: E402
from cheats import Runtime  # noqa: E402
from cheats_editor_tab import CheatsEditorTab  # noqa: E402
from cheats_play_tab import CheatsPlayTab  # noqa: E402
from cheats_store import CheatsStore  # noqa: E402
from debugger_tab import DebuggerTab  # noqa: E402
from klog_tab import KlogTab  # noqa: E402
from disassembler_tab import DisassemblerTab  # noqa: E402
from hex_view import HexEditor  # noqa: E402
from items import ItemStore, SearchCombobox  # noqa: E402
from ps5debug_client import (  # noqa: E402
    PROT_EXEC,
    PROT_READ,
    PROT_WRITE,
    PS5DebugClient,
    SERVER_PORT,
)
from scanner_tab import ScannerTab  # noqa: E402
from scrollable import ScrollFrame  # noqa: E402
import theme  # noqa: E402

SETTINGS_FILE = APP_DIR / "settings.json"
DEFAULT_SETTINGS = {"ip": "192.168.100.15", "port": SERVER_PORT, "theme": "light",
                    "safe_calls": True, "call_gap_ms": 150, "geometry": "1360x900"}


def load_settings() -> dict:
    s = dict(DEFAULT_SETTINGS)
    try:
        s.update(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
    except Exception:
        pass
    return s


def save_settings(s: dict) -> None:
    try:
        SETTINGS_FILE.write_text(json.dumps(s, indent=2), encoding="utf-8")
    except Exception:
        pass

REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
REG_LABELS = {
    "rdi": "RDI  (arg0 / this)",
    "rsi": "RSI  (arg1)",
    "rdx": "RDX  (arg2)",
    "rcx": "RCX  (arg3)",
    "r8": "R8   (arg4)",
    "r9": "R9   (arg5)",
}

ARG_KINDS = (
    "u64 / pointer",
    "i64",
    "u32",
    "i32",
    "float bits",
    "double bits",
)


@dataclass
class RemoteBuffer:
    name: str
    address: int
    size: int
    note: str = ""


@dataclass
class AppState:
    buffers: list[RemoteBuffer] = field(default_factory=list)
    last_rax: int = 0
    selected_pid: Optional[int] = None
    aob_cache: dict = field(default_factory=dict)   # (pid, pattern, ...) -> address found by an aob step


def parse_int(text: str, state: AppState) -> int:
    raw = text.strip()
    if not raw:
        return 0
    low = raw.lower()
    if low in ("rax", "$rax", "last", "last_rax"):
        return state.last_rax & 0xFFFFFFFFFFFFFFFF
    if raw.startswith("@"):
        name = raw[1:].strip()
        buf = find_buffer(state, name)
        if buf is None:
            raise ValueError(f"unknown buffer @{name}")
        return buf.address
    if low.startswith("0x"):
        return int(raw, 16) & 0xFFFFFFFFFFFFFFFF
    if raw.startswith("-"):
        return int(raw, 10) & 0xFFFFFFFFFFFFFFFF
    if raw.isdigit():
        return int(raw, 10) & 0xFFFFFFFFFFFFFFFF
    return int(raw, 0) & 0xFFFFFFFFFFFFFFFF


def find_buffer(state: AppState, name: str) -> Optional[RemoteBuffer]:
    name = name.strip()
    for buf in state.buffers:
        if buf.name == name:
            return buf
    return None


def encode_arg(kind: str, text: str, state: AppState) -> int:
    if kind == "float bits":
        return struct.unpack("<I", struct.pack("<f", float(text.strip() or "0")))[0]
    if kind == "double bits":
        return struct.unpack("<Q", struct.pack("<d", float(text.strip() or "0")))[0]
    value = parse_int(text, state)
    if kind == "u32":
        return value & 0xFFFFFFFF
    if kind == "i32":
        return value & 0xFFFFFFFF
    if kind == "i64":
        return value & 0xFFFFFFFFFFFFFFFF
    return value & 0xFFFFFFFFFFFFFFFF


def build_payload(kind: str, text: str, add_nul: bool) -> bytes:
    body = text.replace("\r\n", "\n")
    if kind == "utf-8":
        data = body.encode("utf-8")
        return data + (b"\x00" if add_nul else b"")
    if kind == "utf-16le":
        data = body.encode("utf-16le")
        return data + (b"\x00\x00" if add_nul else b"")
    if kind == "hex":
        hex_str = "".join(ch for ch in body if ch not in " \t\n,")
        if hex_str.startswith("0x") or hex_str.startswith("0X"):
            hex_str = hex_str[2:]
        if len(hex_str) % 2:
            hex_str = "0" + hex_str
        data = bytes.fromhex(hex_str) if hex_str else b""
        return data + (b"\x00" if add_nul else b"")
    if kind in ("u8 list", "i8 list", "u16 list", "i16 list", "u32 list", "i32 list",
                "u64 list", "i64 list", "f32 list", "f64 list"):
        tokens = [t for t in body.replace(",", " ").split() if t]
        fmt = {
            "u8 list": "B",
            "i8 list": "b",
            "u16 list": "H",
            "i16 list": "h",
            "u32 list": "I",
            "i32 list": "i",
            "u64 list": "Q",
            "i64 list": "q",
            "f32 list": "f",
            "f64 list": "d",
        }[kind]
        packed = b""
        for tok in tokens:
            if fmt in "fd":
                packed += struct.pack("<" + fmt, float(tok))
            else:
                packed += struct.pack("<" + fmt, int(tok, 0))
        return packed + (b"\x00" if add_nul else b"")
    raise ValueError(f"unknown payload kind {kind}")


def decode_value(kind: str, data: bytes) -> str:
    if not data:
        return "(empty)"
    if kind == "hex dump":
        lines = []
        for off in range(0, len(data), 16):
            chunk = data[off : off + 16]
            hexpart = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:04X}  {hexpart:<48}  {ascii_part}")
        return "\n".join(lines)
    if kind == "cstring":
        return data.split(b"\x00", 1)[0].decode("utf-8", "replace")
    if kind == "utf-16le string":
        return data.split(b"\x00\x00", 1)[0].decode("utf-16le", "replace")
    unpackers = {
        "u8": ("<B", 1),
        "i8": ("<b", 1),
        "u16": ("<H", 2),
        "i16": ("<h", 2),
        "u32": ("<I", 4),
        "i32": ("<i", 4),
        "u64 / pointer": ("<Q", 8),
        "i64": ("<q", 8),
        "float": ("<f", 4),
        "double": ("<d", 8),
    }
    fmt, size = unpackers[kind]
    if len(data) < size:
        return f"need {size} bytes, got {len(data)}"
    value = struct.unpack(fmt, data[:size])[0]
    if kind in ("u64 / pointer", "u32", "u16", "u8"):
        return f"0x{value:X}   ({value})"
    return str(value)


class FunctionCallerApp:
    def __init__(self, root: tk.Tk, settings: Optional[dict] = None) -> None:
        self.root = root
        self.settings = settings or load_settings()
        self.client = PS5DebugClient()
        self.client.safe_calls = bool(self.settings.get("safe_calls", True))
        self.client.call_gap = max(0, int(self.settings.get("call_gap_ms", 150))) / 1000.0
        self.client.on_disconnect = lambda why: self.root.after(0, lambda: self._on_lost(why))
        self.state = AppState()
        # source text of each quick-code buffer, so the cheat recorder can store
        # the assembly (with its $variables) instead of frozen machine code
        self.code_sources: dict[str, dict] = {}
        self._quick_saved_code = "mov eax, 1\n"
        self._quick_saved_name = "code0"
        self._quick_saved_vars = ""
        self._maps_cache: list = []  # last memory map seen (labels like eboot.bin+0x1234)
        self._busy = False
        self._busy_token: Optional[object] = None
        self._busy_label = ""
        self._jobs: collections.deque = collections.deque()   # clicks made while busy run after the current one
        # log: kept in memory, shown live in a separate window (button at the bottom).
        # log_line() may be called from any thread; lines are flushed to the UI every 100 ms.
        self._log_lines: list[str] = []
        self._log_pending: collections.deque = collections.deque()
        self._log_win: Optional[tk.Toplevel] = None
        self._log_text: Optional[tk.Text] = None
        self._log_follow = tk.BooleanVar(value=True)
        self.last_log_var = tk.StringVar(value="")

        root.title("PS5 Cheat & Debug Toolkit  -  ps5debug-NG")
        root.geometry(self.settings.get("geometry") or "1360x900")
        root.minsize(1080, 720)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.project_dir = self._start_project()
        self.items = ItemStore(self.project_dir / "items")
        self.item_errors = self.items.reload()
        self._build()
        self.items.on_change.append(self._refresh_item_lists)
        self._refresh_item_lists()
        for e in self.item_errors:
            self.log_line(f"item file error: {e}")
        self._set_status("Disconnected")
        self.cheats_store.reload()
        self.root.after(100, self._flush_log)

    def _build(self) -> None:
        self._build_menu()
        if not self.author() and not self.settings.get("author_asked"):
            self.root.after(600, self.ask_author)      # first run: who makes the cheats
        top = ttk.Frame(self.root, padding=(10, 8, 10, 4))
        top.pack(fill="x")
        row1 = ttk.Frame(top)
        row1.pack(fill="x")

        ttk.Label(row1, text="PS5 IP").pack(side="left")
        self.ip_var = tk.StringVar(value=str(self.settings.get("ip", "192.168.100.15")))
        ip_entry = ttk.Entry(row1, textvariable=self.ip_var, width=16)
        ip_entry.pack(side="left", padx=(4, 8))
        ip_entry.bind("<Return>", lambda _e: self.on_connect())
        ttk.Label(row1, text="Port").pack(side="left")
        self.port_var = tk.StringVar(value=str(self.settings.get("port", SERVER_PORT)))
        ttk.Entry(row1, textvariable=self.port_var, width=6).pack(side="left", padx=(4, 8))
        ttk.Button(row1, text="Connect", style="Accent.TButton", command=self.on_connect).pack(side="left", padx=2)
        ttk.Button(row1, text="Disconnect", command=self.on_disconnect).pack(side="left", padx=2)
        ttk.Button(row1, text="Ping", command=self.on_ping).pack(side="left", padx=2)
        ttk.Button(row1, text="Diagnose", command=self.on_diagnose).pack(side="left", padx=2)
        self.reset_btn = ttk.Button(row1, text="Force reset", command=self.on_force_reset, state="disabled")
        self.reset_btn.pack(side="left", padx=8)
        self.status_var = tk.StringVar()
        self.conn_dot = tk.Label(row1, text="\u25cf", font=(theme.UI_FONT[0], 12), bg=theme.c("bg"),
                                 fg=theme.c("muted"))
        ttk.Label(row1, textvariable=self.status_var, style="Muted.TLabel").pack(side="right")
        self.conn_dot.pack(side="right", padx=(0, 4))

        # second row: process picker (dropdown) + target PID
        row2 = ttk.Frame(top)
        row2.pack(fill="x", pady=(6, 0))
        ttk.Label(row2, text="Process").pack(side="left")
        self.proc_var = tk.StringVar()
        self._proc_map: dict[str, tuple[int, str]] = {}
        self.proc_combo = ttk.Combobox(
            row2, textvariable=self.proc_var, values=(), width=46, state="readonly"
        )
        self.proc_combo.pack(side="left", padx=4)
        self.proc_combo.bind("<<ComboboxSelected>>", self.on_proc_select)
        ttk.Button(row2, text="Refresh", command=self.on_refresh_procs).pack(side="left", padx=2)
        ttk.Button(row2, text="Info", command=self.on_proc_info).pack(side="left", padx=2)
        ttk.Button(row2, text="Maps", command=self.on_maps).pack(side="left", padx=2)
        ttk.Label(row2, text="PID").pack(side="left", padx=(12, 2))
        self.pid_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.pid_var, width=8).pack(side="left")
        self.safe_var = tk.BooleanVar(value=self.client.safe_calls)
        self.safe_var.trace_add("write", lambda *_: self._apply_call_settings())
        ttk.Checkbutton(row2, text="Stack-safe calls", variable=self.safe_var).pack(side="right")

        # bottom status bar (packed before the notebook so it always keeps its space)
        log_bar = ttk.Frame(self.root, padding=(10, 2, 10, 6))
        log_bar.pack(side="bottom", fill="x")
        ttk.Button(log_bar, text="Log", style="Small.TButton", command=self.open_log_window).pack(side="left")
        self.last_log_lbl = ttk.Label(log_bar, textvariable=self.last_log_var, style="Muted.TLabel")
        self.last_log_lbl.pack(side="left", padx=10, fill="x", expand=True)
        self.queue_var = tk.StringVar(value="")
        ttk.Label(log_bar, textvariable=self.queue_var, style="Muted.TLabel").pack(side="right")

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=(4, 2))
        caller_tab = ttk.Frame(nb)
        scanner_tab = ttk.Frame(nb)
        hex_tab = ttk.Frame(nb)
        nb.add(caller_tab, text="Caller")
        nb.add(scanner_tab, text="Scanner")
        nb.add(hex_tab, text="Hex editor")
        disasm_tab = ttk.Frame(nb)
        debug_tab = ttk.Frame(nb)
        nb.add(disasm_tab, text="Disassembler")
        nb.add(debug_tab, text="Debugger")
        self._caller_tab = caller_tab
        self._scanner_tab = scanner_tab
        self._hex_tab = hex_tab
        self._disasm_tab = disasm_tab
        self._debug_tab = debug_tab
        cheats_play_tab = ttk.Frame(nb)
        cheats_editor_tab = ttk.Frame(nb)
        nb.add(cheats_play_tab, text="Cheats")
        nb.add(cheats_editor_tab, text="Cheat Editor")
        klog_tab = ttk.Frame(nb)
        nb.add(klog_tab, text="Kernel log")
        self._klog_tab = klog_tab
        self.notebook = nb
        self._build_hex_tab(hex_tab)
        self._cheats_play_tab = cheats_play_tab
        self._cheats_editor_tab = cheats_editor_tab
        for i, key in enumerate(("1", "2", "3", "4", "5", "6", "7", "8")):
            self.root.bind_all(f"<Control-Key-{key}>", lambda _e, i=i: nb.select(i))

        caller_scroll = ScrollFrame(caller_tab)
        caller_scroll.pack(fill="both", expand=True)
        right = ttk.Frame(caller_scroll.body, padding=4)
        right.pack(fill="both", expand=True)

        call = ttk.LabelFrame(right, text="Function call  (SysV: RIP + RDI..R9 → RAX)", padding=6)
        call.pack(fill="x")

        grid = ttk.Frame(call)
        grid.pack(fill="x")
        ttk.Label(grid, text="Function address (RIP)").grid(row=0, column=0, sticky="w")
        self.rip_var = tk.StringVar()
        ttk.Entry(grid, textvariable=self.rip_var, width=28).grid(row=0, column=1, sticky="we", padx=4)
        ttk.Label(grid, text="rpcstub (leave 0)").grid(row=0, column=2, sticky="w")
        self.stub_var = tk.StringVar(value="0")
        ttk.Entry(grid, textvariable=self.stub_var, width=18).grid(row=0, column=3, sticky="we", padx=4)
        grid.columnconfigure(1, weight=1)
        grid.columnconfigure(3, weight=1)

        ttk.Label(
            call,
            text="Values: hex (0x...), decimal, @buffer_name, or rax. Pointers are just u64 addresses.",
        ).pack(anchor="w", pady=(6, 2))

        ibar = ttk.Frame(call)
        ibar.pack(fill="x", pady=(0, 4))
        ttk.Label(ibar, text="Item list").pack(side="left")
        self.item_list_var = tk.StringVar()
        self.item_list_combo = ttk.Combobox(
            ibar, textvariable=self.item_list_var, values=(), width=22, state="readonly"
        )
        self.item_list_combo.pack(side="left", padx=4)
        self.item_list_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_item_combos())
        ttk.Button(ibar, text="Load items file...", command=self.on_load_items).pack(side="left", padx=2)
        ttk.Label(
            ibar, text='{"item name": id} JSON. Pick an item beside a register; tick "edit" to make it a cheat input.'
        ).pack(side="left", padx=8)

        self.arg_kind: dict[str, tk.StringVar] = {}
        self.arg_val: dict[str, tk.StringVar] = {}
        self.arg_edit: dict[str, tk.BooleanVar] = {}
        self.arg_item_combo: dict[str, SearchCombobox] = {}
        self.arg_item_pick: dict[str, tuple[str, str]] = {}
        args = ttk.Frame(call)
        args.pack(fill="x")
        for i, reg in enumerate(REGS):
            ttk.Label(args, text=REG_LABELS[reg]).grid(row=i, column=0, sticky="w", pady=1)
            kind = tk.StringVar(value=ARG_KINDS[0])
            val = tk.StringVar(value="0")
            self.arg_kind[reg] = kind
            self.arg_val[reg] = val
            ttk.Combobox(args, textvariable=kind, values=ARG_KINDS, width=14, state="readonly").grid(
                row=i, column=1, padx=4
            )
            ttk.Entry(args, textvariable=val, width=30).grid(row=i, column=2, sticky="we", pady=1)
            combo = SearchCombobox(args, width=24)
            combo.grid(row=i, column=3, padx=4)
            combo.bind("<<ComboboxSelected>>", lambda _e, r=reg: self._pick_item(r))
            self.arg_item_combo[reg] = combo
            self.arg_edit[reg] = tk.BooleanVar(value=False)
            ttk.Checkbutton(args, text="edit", variable=self.arg_edit[reg]).grid(row=i, column=4)
        args.columnconfigure(2, weight=1)

        call_row = ttk.Frame(call)
        call_row.pack(fill="x", pady=6)
        ttk.Button(call_row, text="Call function", style="Accent.TButton", command=self.on_call).pack(side="left")
        ttk.Button(call_row, text="Disassemble RIP", command=self.on_disassemble_rip).pack(side="left", padx=6)
        self.rax_var = tk.StringVar(value="RAX =")
        ttk.Label(call_row, textvariable=self.rax_var, font=theme.mono(11, "bold")).pack(side="left", padx=12)

        self.quick_out = tk.StringVar(value="")
        self.quick_win: Optional[tk.Toplevel] = None
        asm_row = ttk.Frame(right)
        asm_row.pack(fill="x", pady=(8, 0))
        ttk.Button(asm_row, text="Assembler...", command=self.open_assembler).pack(side="left")
        ttk.Label(
            asm_row, foreground=theme.c("muted"),
            text="write x86-64, assemble it into memory and call it (opens in its own window)",
        ).pack(side="left", padx=8)
        ttk.Label(right, textvariable=self.quick_out, foreground=theme.c("muted")).pack(anchor="w")

        mid = ttk.Panedwindow(right, orient="horizontal")
        mid.pack(fill="both", expand=True, pady=(8, 0))

        buf_frame = ttk.LabelFrame(mid, text="Remote buffers", padding=6)
        deref_frame = ttk.LabelFrame(mid, text="Dereference / memory", padding=6)
        mid.add(buf_frame, weight=1)
        mid.add(deref_frame, weight=1)

        brow = ttk.Frame(buf_frame)
        brow.pack(fill="x")
        ttk.Label(brow, text="Name").pack(side="left")
        self.buf_name = tk.StringVar(value="buf0")
        ttk.Entry(brow, textvariable=self.buf_name, width=12).pack(side="left", padx=4)
        ttk.Label(brow, text="Size").pack(side="left")
        self.buf_size = tk.StringVar(value="256")
        ttk.Entry(brow, textvariable=self.buf_size, width=10).pack(side="left", padx=4)
        ttk.Button(brow, text="Alloc", command=self.on_alloc).pack(side="left", padx=2)
        ttk.Button(brow, text="Free selected", command=self.on_free).pack(side="left", padx=2)

        prot_row = ttk.Frame(buf_frame)
        prot_row.pack(fill="x", pady=2)
        ttk.Button(prot_row, text="Protect RW", command=lambda: self.on_protect(PROT_READ | PROT_WRITE)).pack(
            side="left", padx=2
        )
        ttk.Button(prot_row, text="Protect RX", command=lambda: self.on_protect(PROT_READ | PROT_EXEC)).pack(
            side="left", padx=2
        )
        ttk.Button(
            prot_row, text="Protect RWX", command=lambda: self.on_protect(PROT_READ | PROT_WRITE | PROT_EXEC)
        ).pack(side="left", padx=2)
        ttk.Button(prot_row, text="Copy pointer", command=self.on_copy_ptr).pack(side="left", padx=8)
        ttk.Button(prot_row, text="Use as RDI", command=lambda: self._use_buf_as("rdi")).pack(side="left")
        ttk.Button(prot_row, text="Open in hex", command=self.on_buf_open_hex).pack(side="left", padx=8)

        self.buf_tree = ttk.Treeview(
            buf_frame, columns=("name", "addr", "size"), show="headings", height=6
        )
        for col, w in (("name", 80), ("addr", 160), ("size", 80)):
            self.buf_tree.heading(col, text=col)
            self.buf_tree.column(col, width=w)
        self.buf_tree.pack(fill="both", expand=True, pady=4)

        ttk.Label(buf_frame, text="Write contents into selected buffer (or address below)").pack(anchor="w")
        wrow = ttk.Frame(buf_frame)
        wrow.pack(fill="x")
        self.payload_kind = tk.StringVar(value="utf-8")
        ttk.Combobox(
            wrow,
            textvariable=self.payload_kind,
            values=(
                "utf-8",
                "utf-16le",
                "hex",
                "u8 list",
                "u32 list",
                "i32 list",
                "u64 list",
                "i64 list",
                "f32 list",
                "f64 list",
            ),
            width=12,
            state="readonly",
        ).pack(side="left")
        self.add_nul = tk.BooleanVar(value=True)
        ttk.Checkbutton(wrow, text="append NUL", variable=self.add_nul).pack(side="left", padx=6)
        ttk.Button(wrow, text="Write to buffer", command=self.on_write_buf).pack(side="left")

        irow = ttk.Frame(buf_frame)
        irow.pack(fill="x", pady=(2, 0))
        ttk.Label(irow, text="Item").pack(side="left")
        self.payload_item_combo = SearchCombobox(irow, width=26)
        self.payload_item_combo.pack(side="left", padx=4)
        ttk.Button(irow, text="Insert id at cursor", command=self.on_insert_item_id).pack(side="left")

        self.payload_text = tk.Text(buf_frame, height=6, wrap="word", font=("Consolas", 10))
        self.payload_text.pack(fill="both", expand=True, pady=4)

        drow = ttk.Frame(deref_frame)
        drow.pack(fill="x")
        ttk.Label(drow, text="Address").pack(side="left")
        self.deref_addr = tk.StringVar()
        ttk.Entry(drow, textvariable=self.deref_addr, width=24).pack(side="left", padx=4, fill="x", expand=True)

        drow2 = ttk.Frame(deref_frame)
        drow2.pack(fill="x", pady=4)
        ttk.Label(drow2, text="Follow ptr").pack(side="left")
        self.follow_n = tk.StringVar(value="0")
        ttk.Entry(drow2, textvariable=self.follow_n, width=5).pack(side="left", padx=4)
        ttk.Label(drow2, text="times, then +").pack(side="left")
        self.deref_off = tk.StringVar(value="0")
        ttk.Entry(drow2, textvariable=self.deref_off, width=12).pack(side="left", padx=4)

        drow3 = ttk.Frame(deref_frame)
        drow3.pack(fill="x")
        self.deref_kind = tk.StringVar(value="u64 / pointer")
        ttk.Combobox(
            drow3,
            textvariable=self.deref_kind,
            values=(
                "u8",
                "i8",
                "u16",
                "i16",
                "u32",
                "i32",
                "u64 / pointer",
                "i64",
                "float",
                "double",
                "cstring",
                "utf-16le string",
                "hex dump",
            ),
            width=18,
            state="readonly",
        ).pack(side="left")
        ttk.Label(drow3, text="bytes").pack(side="left", padx=(8, 2))
        self.deref_len = tk.StringVar(value="8")
        ttk.Entry(drow3, textvariable=self.deref_len, width=8).pack(side="left")
        ttk.Button(drow3, text="Read / deref", command=self.on_deref).pack(side="left", padx=6)

        drow4 = ttk.Frame(deref_frame)
        drow4.pack(fill="x", pady=4)
        ttk.Label(drow4, text="Write value").pack(side="left")
        self.write_val = tk.StringVar()
        ttk.Entry(drow4, textvariable=self.write_val, width=24).pack(side="left", padx=4, fill="x", expand=True)
        ttk.Button(drow4, text="Write primitive", command=self.on_write_primitive).pack(side="left")
        ttk.Button(drow4, text="Use result as RDI", command=lambda: self._use_deref_as("rdi")).pack(
            side="left", padx=4
        )

        self.deref_out = tk.Text(deref_frame, height=10, wrap="word", font=("Consolas", 10))
        self.deref_out.pack(fill="both", expand=True)
        ttk.Button(deref_frame, text="Open address in hex editor", command=self.on_deref_open_hex).pack(
            fill="x", pady=(4, 0)
        )

        # Built last: both Cheats tabs reference widgets (pid_var, rip_var, ...)
        # created above, and share one CheatsStore so toggling/editing a cheat
        # in either tab is reflected in the other.
        self.make_cheat_buffer = RemoteBuffer
        self.cheats_store = CheatsStore(self, RemoteBuffer, self.project_dir)
        self.cheats = CheatsPlayTab(self._cheats_play_tab, self, self.cheats_store)
        self.cheats_editor = CheatsEditorTab(self._cheats_editor_tab, self, self.cheats_store)
        self.debugger = DebuggerTab(self._debug_tab, self)
        self.disassembler = DisassemblerTab(self._disasm_tab, self)
        self.scanner = ScannerTab(self._scanner_tab, self)
        self.klog = KlogTab(self._klog_tab, self)

    def open_assembler(self) -> None:
        """Quick-code assembler in its own window (closing it only hides it, so
        your code and variables are still there next time)."""
        win = self.quick_win
        if win is not None and win.winfo_exists():
            win.deiconify()
            win.lift()
            return
        win = tk.Toplevel(self.root)
        self.quick_win = win
        win.title("Assembler - write x86-64, put it in memory, call it")
        win.geometry("960x620")
        win.minsize(680, 420)
        win.protocol("WM_DELETE_WINDOW", win.withdraw)
        box = ttk.Frame(win, padding=10)
        box.pack(fill="both", expand=True)

        help_lbl = ttk.Label(
            box, justify="left",
            text="Writes machine code into a reusable buffer, then uses it as RIP. Write @buf0, "
                 "module(eboot.bin)+0x10 or $var right in the code (e.g. mov rdi, @buf0); they become live "
                 "addresses. {expr} also works for pointer chains. ';' starts a comment. ret is added if missing.",
        )
        help_lbl.pack(anchor="w", fill="x")
        help_lbl.bind("<Configure>", lambda e: help_lbl.configure(wraplength=max(300, e.width - 12)))

        # bottom rows are packed first so the editor above gets all the leftover space
        out_lbl = ttk.Label(box, textvariable=self.quick_out, foreground=theme.c("muted"), justify="left")
        out_lbl.pack(side="bottom", anchor="w", fill="x", pady=(4, 0))
        out_lbl.bind("<Configure>", lambda e: out_lbl.configure(wraplength=max(300, e.width - 12)))
        vrow = ttk.Frame(box)
        vrow.pack(side="bottom", fill="x", pady=(6, 0))
        qrow = ttk.Frame(box)
        qrow.pack(side="bottom", fill="x", pady=(6, 0))

        tf = ttk.Frame(box)
        tf.pack(fill="both", expand=True, pady=(6, 0))
        self.quick_asm = tk.Text(tf, height=12, wrap="none", font=("Consolas", 11), undo=True)
        ys = ttk.Scrollbar(tf, orient="vertical", command=self.quick_asm.yview)
        xs = ttk.Scrollbar(tf, orient="horizontal", command=self.quick_asm.xview)
        self.quick_asm.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.quick_asm.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        tf.grid_rowconfigure(0, weight=1)
        tf.grid_columnconfigure(0, weight=1)
        self.quick_asm.insert("1.0", self._quick_saved_code)
        self.quick_asm.bind("<Control-Return>", lambda e: (self.on_quick_assemble(False), "break")[1])

        self.quick_name = tk.StringVar(value=self._quick_saved_name)
        ttk.Label(qrow, text="Name").pack(side="left")
        self.quick_name_combo = ttk.Combobox(qrow, textvariable=self.quick_name, values=self._code_names(), width=14)
        self.quick_name_combo.pack(side="left", padx=4)
        ttk.Button(qrow, text="New", width=5, command=self.on_quick_new_name).pack(side="left", padx=(0, 10))
        self.quick_prot = tk.StringVar(value="rx")
        ttk.Label(qrow, text="Prot").pack(side="left")
        ttk.Combobox(qrow, textvariable=self.quick_prot, values=("rx", "rwx"), width=5,
                     state="readonly").pack(side="left", padx=4)
        self.quick_auto_ret = tk.BooleanVar(value=True)
        ttk.Checkbutton(qrow, text="auto ret", variable=self.quick_auto_ret).pack(side="left", padx=6)
        self.quick_auto_frame = tk.BooleanVar(value=True)
        ttk.Checkbutton(qrow, text="auto stack frame", variable=self.quick_auto_frame).pack(side="left", padx=(0, 6))
        ttk.Button(qrow, text="Preview", command=self.on_quick_preview).pack(side="left", padx=6)
        ttk.Button(qrow, text="Assemble -> set as RIP  (Ctrl+Enter)",
                   command=lambda: self.on_quick_assemble(False)).pack(side="left", padx=2)
        ttk.Button(qrow, text="Assemble & Call now",
                   command=lambda: self.on_quick_assemble(True)).pack(side="left", padx=2)
        ttk.Button(qrow, text="Hide", command=win.withdraw).pack(side="right")

        ttk.Label(vrow, text="Variables").pack(side="left")
        self.quick_vars = tk.StringVar(value=self._quick_saved_vars)
        ttk.Entry(vrow, textvariable=self.quick_vars).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Label(
            vrow, foreground=theme.c("muted"),
            text="name=value, comma separated, e.g.  var=0x10, item=@buf0  ->  $var, $item  ($ret = last RAX)",
        ).pack(side="left")
        self.quick_asm.focus_set()

    def on_disassemble_rip(self) -> None:
        try:
            addr = self.eval_full(self.rip_var.get())
        except Exception as exc:
            self._fail(exc)
            return
        self.show_in_disassembler(addr)

    def show_in_disassembler(self, addr: int) -> None:
        self.notebook.select(self._disasm_tab)
        self.disassembler.goto(addr)

    def eval_full(self, text: str) -> int:
        """Any cheat expression: numbers, @buf, rax, module(x), [ptr], $var, + - *."""
        text = text.strip()
        try:
            return self.eval_int(text)  # fast path, no console traffic
        except Exception:
            pass
        rt = Runtime(self.client, self.state, self._pid(), RemoteBuffer, lambda m: None, [])
        rt.vars["ret"] = self.state.last_rax & 0xFFFFFFFFFFFFFFFF
        return rt.ev(text) & 0xFFFFFFFFFFFFFFFF

    def _build_hex_tab(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Address").pack(side="left")
        self.hex_addr = tk.StringVar()
        addr_entry = ttk.Entry(bar, textvariable=self.hex_addr, width=28)
        addr_entry.pack(side="left", padx=4)
        addr_entry.bind("<Return>", lambda _e: self.on_hex_go())
        ttk.Label(bar, text="Bytes").pack(side="left")
        self.hex_len = tk.StringVar(value="256")
        ttk.Combobox(
            bar,
            textvariable=self.hex_len,
            values=("64", "128", "256", "512", "1024", "2048", "4096"),
            width=8,
        ).pack(side="left", padx=4)
        ttk.Button(bar, text="Go", command=self.on_hex_go).pack(side="left", padx=2)
        ttk.Button(bar, text="Refresh", command=self.on_hex_go).pack(side="left", padx=2)
        ttk.Button(bar, text="Prev page", command=lambda: self.on_hex_page(-1)).pack(side="left", padx=2)
        ttk.Button(bar, text="Next page", command=lambda: self.on_hex_page(1)).pack(side="left", padx=2)

        bar2 = ttk.Frame(parent, padding=(6, 0, 6, 6))
        bar2.pack(fill="x")
        ttk.Button(bar2, text="Goto RIP", command=lambda: self._hex_goto_field(self.rip_var)).pack(
            side="left", padx=2
        )
        ttk.Button(bar2, text="Goto RAX", command=lambda: self._hex_goto_value(self.state.last_rax)).pack(
            side="left", padx=2
        )
        ttk.Button(bar2, text="Goto deref", command=self.on_deref_open_hex).pack(side="left", padx=2)
        ttk.Button(bar2, text="Goto selected buffer", command=self.on_buf_open_hex).pack(side="left", padx=2)
        ttk.Button(bar2, text="Write changes", command=self.on_hex_write).pack(side="left", padx=12)
        ttk.Button(bar2, text="Revert", command=self.on_hex_revert).pack(side="left", padx=2)
        ttk.Button(bar2, text="Use cursor as RDI", command=self.on_hex_use_rdi).pack(side="left", padx=8)

        self.hex_status = tk.StringVar(value="No data loaded")
        ttk.Label(parent, textvariable=self.hex_status, padding=(8, 0)).pack(fill="x")

        self.hex_view = HexEditor(parent, on_cursor=self._update_hex_status, on_message=self.log_line)
        self.hex_view.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.hex_view.text.bind("<Prior>", lambda _e: self.on_hex_page(-1) or "break")
        self.hex_view.text.bind("<Next>", lambda _e: self.on_hex_page(1) or "break")
        bar3 = ttk.Frame(parent, padding=(6, 0, 6, 6))
        bar3.pack(fill="x", after=bar2)
        ttk.Label(bar3, text="Selection:").pack(side="left", padx=(2, 4))
        copy_btn = ttk.Menubutton(bar3, text="Copy as...")
        copy_btn.configure(menu=self.hex_view.build_menu(copy_btn))
        copy_btn.pack(side="left", padx=2)
        ttk.Button(bar3, text="Select all", command=self.hex_view.select_all).pack(side="left", padx=2)
        ttk.Button(bar3, text="Save selection / view...", command=self.hex_view.save_file).pack(
            side="left", padx=2
        )
        ttk.Button(bar3, text="Dump region from console...", command=self.on_dump_region).pack(
            side="left", padx=12
        )
        hint = ttk.Label(
            parent,
            text="Drag / Shift+click / Shift+arrows to select.  Ctrl+C copies hex, Ctrl+Shift+C the address, "
            "right-click for more formats.  Type 0-9 / A-F to edit (yellow = not yet written).",
            padding=(8, 0, 8, 8),
        )
        hint.pack(fill="x")

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)
        if self.client.connected:
            color = theme.c("warn") if self._busy else theme.c("ok")
        else:
            color = theme.c("danger") if "lost" in text.lower() else theme.c("muted")
        try:
            self.conn_dot.configure(fg=color)
        except (tk.TclError, AttributeError):
            pass

    # ---- menu / settings ---------------------------------------------
    def _build_menu(self) -> None:
        mb = tk.Menu(self.root)
        f = tk.Menu(mb, tearoff=0)
        f.add_command(label="Open log window", command=self.open_log_window)
        f.add_command(label="Save log...", command=self._log_save)
        f.add_separator()
        f.add_command(label="Exit", command=self.on_close)
        mb.add_cascade(label="File", menu=f)
        c = tk.Menu(mb, tearoff=0)
        c.add_command(label="Connect", command=self.on_connect)
        c.add_command(label="Disconnect", command=self.on_disconnect)
        c.add_command(label="Ping", command=self.on_ping)
        c.add_command(label="Diagnose", command=self.on_diagnose)
        c.add_command(label="Force reset", command=self.on_force_reset)
        mb.add_cascade(label="Connection", menu=c)
        v = tk.Menu(mb, tearoff=0)
        self._theme_var = tk.StringVar(value=theme.name())
        v.add_radiobutton(label="Light theme", value="light", variable=self._theme_var, command=self._set_theme)
        v.add_radiobutton(label="Dark theme", value="dark", variable=self._theme_var, command=self._set_theme)
        mb.add_cascade(label="View", menu=v)
        tl = tk.Menu(mb, tearoff=0)
        tl.add_command(label="Python script…   (Ctrl+P)", command=lambda: self.open_script_window())
        tl.add_command(label="Function logger…", command=lambda: self.open_func_logger())
        tl.add_command(label="Pointer scan…", command=lambda: self.scanner.open_pointer_scan())
        mb.add_cascade(label="Tools", menu=tl)
        self.root.bind_all("<Control-p>", lambda _e: self.open_script_window())
        st = tk.Menu(mb, tearoff=0)
        st.add_command(label="Remote call safety...", command=self.open_call_settings)
        st.add_command(label="Author name...", command=lambda: self.ask_author(first=False))
        mb.add_cascade(label="Settings", menu=st)
        self.root.configure(menu=mb)

    # ---- cheat projects / author --------------------------------------
    def _start_project(self) -> Path:
        import projects                                   # noqa: PLC0415
        p = Path(self.settings.get("project") or projects.DEFAULT_DIR)
        if not p.is_dir():
            p = projects.DEFAULT_DIR
        return projects.ensure(p)

    def recent_projects(self) -> list[Path]:
        import projects                                   # noqa: PLC0415
        out = [projects.DEFAULT_DIR]
        for x in [self.settings.get("project", "")] + list(self.settings.get("projects", [])):
            if x and Path(x).is_dir() and Path(x) not in out:
                out.append(Path(x))
        return out

    def switch_project(self, path: Path) -> None:
        """Make `path` the active project: cheats, item lists and exports all live there."""
        import projects                                   # noqa: PLC0415
        path = projects.ensure(Path(path))
        if self.cheats_store.enabled:
            self.log_line("note: cheats that are ON stay on in the game after switching project - "
                          "turn them off in the old project first if needed")
        self.cheats_store.enabled.clear()
        self.project_dir = path
        self.settings["project"] = str(path)
        rec = [str(x) for x in self.recent_projects() if x != projects.DEFAULT_DIR and x != path]
        self.settings["projects"] = ([str(path)] if path != projects.DEFAULT_DIR else []) + rec[:9]
        save_settings(self.settings)
        self.items.folder = path / "items"
        for e in self.items.reload():
            self.log_line(f"item list error: {e}")
        for cb in self.items.on_change:
            cb()
        self.cheats_store.folder = path
        self.cheats_store.reload()
        self.log_line(f"project: {projects.info(path)['name']}  ({path})")

    def author(self) -> str:
        return str(self.settings.get("author", "")).strip()

    def ask_author(self, first: bool = True) -> None:
        win = tk.Toplevel(self.root)
        win.title("Your author name" if first else "Author name")
        win.transient(self.root)
        win.resizable(False, False)
        f = ttk.Frame(win, padding=14)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text=("Welcome! " if first else "") + "What name should go on the cheats you make?",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(f, text="Used as the author of new games / cheats and as Moder / credits when you export "
                          ".shn, .mc4 and GoldHEN .json files.  Change it any time: Settings > Author name.",
                  justify="left", wraplength=440).pack(anchor="w", pady=(4, 8))
        v = tk.StringVar(value=self.author())
        e = ttk.Entry(f, textvariable=v, width=36)
        e.pack(anchor="w", fill="x")
        e.focus_set()

        def ok() -> None:
            name = v.get().strip()
            if not name:
                messagebox.showerror("Author name", "Enter a name (a nickname is fine).", parent=win)
                return
            self.settings["author"] = name
            save_settings(self.settings)
            self.log_line(f"author name: {name}")
            win.destroy()

        def later() -> None:
            self.settings.setdefault("author", "")
            self.settings["author_asked"] = True
            save_settings(self.settings)
            win.destroy()

        b = ttk.Frame(f)
        b.pack(fill="x", pady=(10, 0))
        ttk.Button(b, text="Save", style="Accent.TButton", command=ok).pack(side="right")
        ttk.Button(b, text="Later" if first else "Cancel", command=later if first else win.destroy).pack(side="right", padx=6)
        win.bind("<Return>", lambda _e: ok())
        win.protocol("WM_DELETE_WINDOW", later if first else win.destroy)
        win.grab_set()

    def open_func_logger(self, addr: Optional[int] = None) -> None:
        from func_logger_window import FuncLoggerWindow   # noqa: PLC0415
        FuncLoggerWindow(self, addr)

    def open_script_window(self, code: Optional[str] = None) -> None:
        from script_window import ScriptWindow            # noqa: PLC0415
        ScriptWindow.open(self, code)

    def open_script_window_for(self, code: str, on_save, title: str) -> None:
        from script_window import ScriptWindow            # noqa: PLC0415
        ScriptWindow.open(self, code, on_save, title)

    def _set_theme(self) -> None:
        self.settings["theme"] = self._theme_var.get()
        save_settings(self.settings)
        messagebox.showinfo("Theme", "The new theme is used the next time you start the tool.", parent=self.root)

    def _apply_call_settings(self) -> None:
        self.client.safe_calls = bool(self.safe_var.get())
        self.settings["safe_calls"] = self.client.safe_calls
        self.settings["call_gap_ms"] = int(round(self.client.call_gap * 1000))
        save_settings(self.settings)

    def open_call_settings(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Remote call safety")
        win.transient(self.root)
        win.resizable(False, False)
        f = ttk.Frame(win, padding=14)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Remote call safety", style="Big.TLabel").pack(anchor="w")
        ttk.Label(f, style="Muted.TLabel", wraplength=470, justify="left", text=(
            "ps5debug-NG runs a call / alloc / free by borrowing (ptrace-hijacking) a live game thread and "
            "using that thread's own stack.\n\n"
            "Stack-safe calls: the call goes through a tiny trampoline that moves the stack 2 KB away from the "
            "borrowed thread's frame, aligns it to 16 bytes and leaves 256 bytes of scratch, so code that "
            "writes stack arguments ([rsp+8]...) cannot corrupt the game thread. Keep this on.\n\n"
            "Minimum gap: every borrow stops and resumes the whole game, so requests are spaced at least "
            "this far apart, even when a script or 'Add all items' fires them back to back.")).pack(
            anchor="w", pady=(4, 10))
        sv = tk.BooleanVar(value=self.client.safe_calls)
        gv = tk.StringVar(value=str(int(round(self.client.call_gap * 1000))))
        ttk.Checkbutton(f, text="Stack-safe calls (trampoline)", variable=sv).pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(anchor="w", pady=(8, 0))
        ttk.Label(row, text="Minimum gap between calls (ms)").pack(side="left")
        ttk.Spinbox(row, from_=0, to=5000, increment=50, textvariable=gv, width=7).pack(side="left", padx=6)

        def ok() -> None:
            try:
                gap = max(0, int(gv.get().strip() or "0"))
            except ValueError:
                messagebox.showerror("Settings", "gap must be a whole number of ms", parent=win)
                return
            self.client.call_gap = gap / 1000.0
            self.safe_var.set(sv.get())
            self._apply_call_settings()
            self.log_line(f"call safety: stack-safe={'on' if sv.get() else 'off'}, gap={gap} ms")
            win.destroy()

        b = ttk.Frame(f)
        b.pack(fill="x", pady=(14, 0))
        ttk.Button(b, text="Save", style="Accent.TButton", command=ok).pack(side="right")
        ttk.Button(b, text="Cancel", command=win.destroy).pack(side="right", padx=6)

    def on_close(self) -> None:
        try:
            self.settings["ip"] = self.ip_var.get().strip()
            self.settings["port"] = int(self.port_var.get().strip() or SERVER_PORT)
            if self.root.state() == "normal":
                self.settings["geometry"] = self.root.geometry()
            save_settings(self.settings)
        except Exception:
            pass
        try:
            self.scanner.disconnect()
        except Exception:
            pass
        try:
            self.klog.close()
        except Exception:
            pass
        self.client.close()
        self.root.destroy()

    # ---- item lists -------------------------------------------------
    def _refresh_item_lists(self) -> None:
        names = self.items.names()
        self.item_list_combo.configure(values=names)
        if names and self.item_list_var.get() not in names:
            self.item_list_var.set(names[0])
        self._refresh_item_combos()

    def _refresh_item_combos(self) -> None:
        vals = sorted(self.items.items(self.item_list_var.get()), key=str.lower)
        for c in self.arg_item_combo.values():
            c.set_values(vals)
        self.payload_item_combo.set_values(vals)

    def on_load_items(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Load items file(s)", filetypes=[("Items JSON", "*.json"), ("All", "*.*")]
        )
        for p in paths:
            try:
                name = self.items.import_file(Path(p))
                self.item_list_var.set(name)
                self._refresh_item_combos()
                self.log_line(f"loaded item list '{name}' ({len(self.items.items(name))} items)")
            except Exception as exc:
                self._fail(exc)

    def _pick_item(self, reg: str) -> None:
        lst, name = self.item_list_var.get(), self.arg_item_combo[reg].get()
        value = self.items.lookup(lst, name)
        if value is None:
            return
        self.arg_val[reg].set(f"0x{value:X}")
        self.arg_item_pick[reg] = (lst, name)
        self.log_line(f"{reg} = {name} (0x{value:X})")

    def on_insert_item_id(self) -> None:
        lst, name = self.item_list_var.get(), self.payload_item_combo.get()
        value = self.items.lookup(lst, name)
        if value is None:
            self._fail(ValueError("pick an item from the list first"))
            return
        self.payload_text.insert("insert", f"{value} ")

    def eval_int(self, text: str) -> int:
        return parse_int(text, self.state)

    def eval_arg(self, kind: str, text: str) -> int:
        return encode_arg(kind, text, self.state)

    LOG_MAX_LINES = 20000

    def log_line(self, text: str) -> None:
        """Thread-safe: queue the line; _flush_log puts it on screen (batched, so
        thousands of lines from a bulk run do not freeze the window)."""
        self._log_pending.append(str(text))

    def _flush_log(self) -> None:
        try:
            if self._log_pending:
                batch = []
                while self._log_pending:
                    batch.append(self._log_pending.popleft())
                self._log_lines.extend(batch)
                if len(self._log_lines) > self.LOG_MAX_LINES:
                    del self._log_lines[: len(self._log_lines) - self.LOG_MAX_LINES + self.LOG_MAX_LINES // 10]
                last = batch[-1]
                self.last_log_var.set(last.splitlines()[0][:200] if last else "")
                box = self._log_text
                if box is not None:
                    try:
                        box.configure(state="normal")
                        box.insert("end", "\n".join(batch) + "\n")
                        if int(box.index("end-1c").split(".")[0]) > self.LOG_MAX_LINES:
                            box.delete("1.0", f"{self.LOG_MAX_LINES // 10}.0")
                        box.configure(state="disabled")
                        if self._log_follow.get():
                            box.see("end")
                    except tk.TclError:
                        self._log_text = None
        finally:
            self.root.after(100, self._flush_log)

    def open_log_window(self) -> None:
        """Live log in its own window (reopening shows everything logged so far)."""
        if self._log_win is not None:
            try:
                self._log_win.deiconify()
                self._log_win.lift()
                return
            except tk.TclError:
                self._log_win = None
        win = tk.Toplevel(self.root)
        self._log_win = win
        win.title("Log (live)")
        win.geometry("900x480")

        bar = ttk.Frame(win, padding=6)
        bar.pack(fill="x")
        ttk.Checkbutton(bar, text="Follow newest", variable=self._log_follow,
                        command=lambda: self._log_text and self._log_follow.get() and self._log_text.see("end")
                        ).pack(side="left")
        ttk.Button(bar, text="Clear", command=self._log_clear).pack(side="left", padx=8)
        ttk.Button(bar, text="Copy all", command=self._log_copy).pack(side="left")
        ttk.Button(bar, text="Save...", command=self._log_save).pack(side="left", padx=8)

        wrap = ttk.Frame(win)
        wrap.pack(fill="both", expand=True)
        box = tk.Text(wrap, wrap="word", font=("Consolas", 10), state="normal")
        ys = ttk.Scrollbar(wrap, orient="vertical", command=box.yview)
        box.configure(yscrollcommand=ys.set)
        ys.pack(side="right", fill="y")
        box.pack(side="left", fill="both", expand=True)
        box.insert("end", "\n".join(self._log_lines) + ("\n" if self._log_lines else ""))
        box.configure(state="disabled")
        box.see("end")
        self._log_text = box

        def on_close() -> None:
            self._log_text = None
            self._log_win = None
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

    def _log_clear(self) -> None:
        self._log_lines.clear()
        if self._log_text is not None:
            self._log_text.configure(state="normal")
            self._log_text.delete("1.0", "end")
            self._log_text.configure(state="disabled")
        self.last_log_var.set("")

    def _log_copy(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self._log_lines))

    def _log_save(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self._log_win, defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")], initialfile="ps5debug_log.txt")
        if path:
            Path(path).write_text("\n".join(self._log_lines) + "\n", encoding="utf-8")
            self.last_log_var.set(f"log saved to {path}")

    def _pid(self) -> int:
        return int(self.pid_var.get().strip(), 0)

    MAX_QUEUED = 20

    def _run_bg(self, fn: Callable[[], None], busy_msg: str) -> None:
        """Run `fn` on a worker thread.  Requests made while one is running are
        queued and run in order (one console request at a time)."""
        if self._busy:
            if len(self._jobs) >= self.MAX_QUEUED:
                self.log_line("busy: too many queued requests - wait (or press Force reset)")
                return
            self._jobs.append((fn, busy_msg))
            self.queue_var.set(f"{len(self._jobs)} queued")
            return
        self._busy = True
        self._busy_label = busy_msg
        self._busy_token = object()
        self._set_status(busy_msg)
        self.reset_btn.configure(state="normal")
        self.root.after(6000, lambda t=self._busy_token: self._watchdog(t, 6))
        token = self._busy_token

        def wrapper() -> None:
            try:
                fn()
            except Exception as exc:
                self.root.after(0, lambda e=exc: self._fail(e))
            finally:
                self.root.after(0, lambda: self._idle(token))

        threading.Thread(target=wrapper, daemon=True).start()

    def _watchdog(self, token: object, waited: int) -> None:
        # Fires every few seconds while a request is outstanding, so a slow or
        # hung request is visibly "still working" instead of silently frozen.
        if not self._busy or token is not self._busy_token:
            return
        self.log_line(f"... still on '{self._busy_label}' after {waited}s "
                      f"(press Force reset if this looks stuck)")
        self.root.after(6000, lambda: self._watchdog(token, waited + 6))

    def _idle(self, token: object = None) -> None:
        if token is not None and token is not self._busy_token:
            return          # a Force reset already moved on
        self._busy = False
        self._busy_token = None
        self.reset_btn.configure(state="disabled")
        if self.client.connected:
            self._set_status(f"Connected  {self.client.host}:{self.client.port}")
        else:
            self._set_status("Disconnected")
        if self._jobs:
            fn, msg = self._jobs.popleft()
            self.queue_var.set(f"{len(self._jobs)} queued" if self._jobs else "")
            self._run_bg(fn, msg)
        else:
            self.queue_var.set("")

    def _fail(self, exc: BaseException) -> None:
        """Errors go to the log and a red status line (no modal popup to click away)."""
        msg = str(exc) or exc.__class__.__name__
        self.log_line(f"error: {msg}")
        try:
            self.last_log_lbl.configure(style="Bad.TLabel")
            self.root.after(8000, lambda: self.last_log_lbl.configure(style="Muted.TLabel"))
        except (tk.TclError, AttributeError):
            pass
        self.root.bell()

    def _on_lost(self, why: str) -> None:
        self.log_line(f"connection lost: {why}")
        self._set_status("Connection lost - press Connect")
        try:
            self.scanner.disconnect()
        except Exception:
            pass

    def on_diagnose(self) -> None:
        """Walk the connection layer by layer with timings, so a hang can be pinned
        on the console, the game process, or memory allocation specifically."""
        if not self.client.connected:
            self.log_line("diagnose: not connected - press Connect first")
            return
        try:
            pid: Optional[int] = self._pid()
        except Exception:
            pid = None

        def work() -> None:
            import time as _t

            def say(m: str) -> None:
                self.root.after(0, lambda: self.log_line(m))

            def step(label: str, fn):
                t = _t.time()
                try:
                    r = fn()
                except Exception as exc:
                    say(f"  FAIL  {label}: {exc}")
                    return None, False
                say(f"  ok    {label}  ({_t.time() - t:.2f}s){'  ' + str(r) if r else ''}")
                return r, True

            say("--- diagnose ---")
            _, ok = step("ping console", self.client.ping)
            if not ok:
                say("  -> the console is not answering at all: the payload is not running, the connection died, "
                    "or the console is in rest mode. Reconnect (resend the payload if needed).")
                return
            if pid is None:
                say("  -> enter / pick a Target PID to test the game process too")
                return
            _, ok = step("process info", lambda: (lambda i: f"{i.name} {i.titleid}")(self.client.proc_info(pid)))
            maps, ok_maps = step("memory maps", lambda: self.client.maps(pid))
            if ok_maps and maps:
                rd = next((m for m in maps if m.prot & 1), None)
                if rd:
                    step(f"read 16 bytes @0x{rd.start:X}", lambda: self.client.read(pid, rd.start, 16).hex(" "))
            addr, ok_alloc = step("alloc 0x1000", lambda: self.client.alloc(pid, 0x1000, 12.0))
            if ok_alloc:
                step("free 0x1000", lambda: self.client.free(pid, addr, 0x1000))
                say("  -> everything answered. If something still hangs it is the specific call/code you ran.")
            elif not self.client.connected:
                say("  -> ping/info/maps work but ALLOC does not answer: the game process is stuck. Common "
                    "causes: a called function that never returned (e.g. an infinite loop in a code buffer), "
                    "or the debugger left the game stopped. Detach the debugger / restart the game.")

        self._run_bg(work, "Diagnosing...")

    def on_force_reset(self) -> None:
        """Unstick a hung request: force-closes the socket (which breaks any
        blocked recv/send in the background thread), drops queued requests and
        clears the busy flag. You'll need to Connect again afterwards."""
        self.client.close()
        self._jobs.clear()
        self.queue_var.set("")
        self._busy = False
        self._busy_token = None
        self.reset_btn.configure(state="disabled")
        self._set_status("Disconnected (reset)")
        self.log_line("force reset: closed the connection - press Connect to resume")
        try:
            self.scanner.disconnect()
        except Exception:
            pass

    def on_connect(self) -> None:
        host = self.ip_var.get().strip()
        port = int(self.port_var.get().strip() or SERVER_PORT)

        self.settings["ip"], self.settings["port"] = host, port
        save_settings(self.settings)
        try:
            self.scanner.disconnect()
        except Exception:
            pass

        def work() -> None:
            self.client.connect(host, port)
            ver = self.client.version()
            brand = self.client.branding().split("\x00", 1)[0]
            fw = self.client.fw_version()
            self.root.after(
                0,
                lambda: self.log_line(f"connected {host}:{port}  proto={ver}  fw={fw}  {brand}"),
            )
            self.root.after(0, lambda: self.klog.on_console_connected(host))
            try:
                procs = self.client.list_processes()
                self.root.after(0, lambda: self._fill_procs(procs))
            except Exception as exc:  # connecting still succeeded
                self.root.after(0, lambda e=exc: self.log_line(f"could not list processes: {e}"))

        self._run_bg(work, "Connecting...")

    def on_disconnect(self) -> None:
        self.client.close()
        try:
            self.klog.stop()
        except Exception:
            pass
        try:
            self.scanner.disconnect()
        except Exception:
            pass
        self._set_status("Disconnected")
        self.log_line("disconnected")

    def on_ping(self) -> None:
        def work() -> None:
            self.client.ping()
            self.root.after(0, lambda: self.log_line("pong"))

        self._run_bg(work, "Pinging...")

    def on_refresh_procs(self) -> None:
        def work() -> None:
            procs = self.client.list_processes()
            self.root.after(0, lambda: self._fill_procs(procs))

        self._run_bg(work, "Listing processes...")

    def _fill_procs(self, procs) -> None:
        keep = self.pid_var.get().strip()
        self._proc_map = {}
        labels = []
        for p in procs:
            label = f"{p.pid}  {p.name}"
            self._proc_map[label] = (p.pid, p.name)
            labels.append(label)
        self.proc_combo.configure(values=labels)
        # keep the current selection if that process is still running
        match = next((l for l, (pid, _n) in self._proc_map.items() if str(pid) == keep), "")
        self.proc_var.set(match)
        self.log_line(f"listed {len(procs)} processes")

    def on_proc_select(self, _evt=None) -> None:
        picked = self._proc_map.get(self.proc_var.get())
        if not picked:
            return
        pid, name = picked
        self.pid_var.set(str(pid))
        self.state.selected_pid = int(pid)
        self.log_line(f"target pid={pid} ({name})")

    def on_proc_info(self) -> None:
        pid = self._pid()

        def work() -> None:
            info = self.client.proc_info(pid)
            self.root.after(
                0,
                lambda: self.log_line(
                    f"info pid={info.pid} name={info.name} title={info.titleid} path={info.path}"
                ),
            )

        self._run_bg(work, "Process info...")

    def on_maps(self) -> None:
        pid = self._pid()

        def work() -> None:
            maps = self.client.maps(pid)
            lines = [
                f"{m.start:016X}-{m.end:016X} prot={m.prot:x}  {m.name}" for m in maps[:80]
            ]
            extra = "" if len(maps) <= 80 else f"\n... {len(maps) - 80} more"
            self.root.after(0, lambda: self.log_line("maps:\n" + "\n".join(lines) + extra))

        self._run_bg(work, "Reading maps...")

    def on_call(self) -> None:
        try:
            pid = self._pid()
            rip = parse_int(self.rip_var.get(), self.state)
            stub = parse_int(self.stub_var.get(), self.state)
            args = {
                reg: encode_arg(self.arg_kind[reg].get(), self.arg_val[reg].get(), self.state)
                for reg in REGS
            }
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            rax = self.client.call(pid, rip, rpcstub=stub, **args)
            self.state.last_rax = rax
            signed = struct.unpack("<q", struct.pack("<Q", rax))[0]
            text = f"RAX = 0x{rax:X}   ({rax} / signed {signed})"
            self.root.after(0, lambda: self._show_rax(text, rip, args, rax))

        self._run_bg(work, "Calling...")

    def _show_rax(self, text, rip, args, rax) -> None:
        self.rax_var.set(text)
        self.log_line(
            f"call rip=0x{rip:X} rdi=0x{args['rdi']:X} rsi=0x{args['rsi']:X} "
            f"rdx=0x{args['rdx']:X} rcx=0x{args['rcx']:X} r8=0x{args['r8']:X} "
            f"r9=0x{args['r9']:X}  -> {text}"
        )

    # ---- quick code (assemble directly from the Caller tab) ---------
    @staticmethod
    def _split_quick_vars(text: str) -> list[tuple[str, str]]:
        """'a=0x10, b=@buf0' -> [('a', '0x10'), ('b', '@buf0')]"""
        out = []
        for part in re.split(r"[,\n]+", text):
            part = part.strip()
            if not part:
                continue
            name, eq, expr = part.partition("=")
            name = name.strip().lstrip("$")
            if not eq or not expr.strip() or not re.fullmatch(r"[A-Za-z_]\w*", name):
                raise ValueError(f"variable '{part}': write it as name=value")
            out.append((name, expr.strip()))
        return out

    @classmethod
    def _parse_quick_vars(cls, text: str, ev, store: dict, strict: bool = True) -> None:
        """Evaluate the Variables box into `store` left to right, so later ones
        may use earlier ones as $a."""
        try:
            pairs = cls._split_quick_vars(text)
        except ValueError:
            if strict:
                raise
            return
        for name, expr in pairs:
            try:
                store[name] = ev(expr) & 0xFFFFFFFFFFFFFFFF
            except Exception:
                if strict:
                    raise

    def _quick_preview_asm(self) -> tuple[str, list[str]]:
        """Resolved asm for the live preview. Names we can't resolve without
        talking to the console (module(), $var, unknown buffers) preview as 0."""
        unresolved: list[str] = []
        known: dict[str, int] = {"ret": self.state.last_rax}
        self._parse_quick_vars(self.quick_vars.get(), self.eval_int, known, strict=False)

        def res(expr: str) -> int:
            if expr.startswith("$") and expr[1:] in known:
                return known[expr[1:]]
            try:
                return self.eval_int(expr)
            except Exception:
                unresolved.append(expr)
                return 0

        code = self.quick_asm.get("1.0", "end-1c")
        resolved = asmgen.substitute(code, res)
        self._quick_frame = 0
        if self.quick_auto_frame.get():
            resolved, self._quick_frame = asmgen.auto_frame(resolved)
        return asmgen.ensure_ret(resolved, self.quick_auto_ret.get()), unresolved

    def on_quick_preview(self) -> None:
        try:
            resolved, unresolved = self._quick_preview_asm()
            raw = asmgen.assemble(resolved)
            note = f"   (resolved at run time: {', '.join(dict.fromkeys(unresolved))})" if unresolved else ""
            if getattr(self, "_quick_frame", 0):
                note += f"   [auto stack frame: sub rsp, 0x{self._quick_frame:X} ... add rsp before ret]"
            self.quick_out.set(
                f"{len(raw)} bytes:  {raw[:48].hex(' ')}{' ...' if len(raw) > 48 else ''}{note}"
            )
        except asmgen.AsmError as exc:
            self.quick_out.set(f"error: {exc}")
        except Exception as exc:
            self.quick_out.set(f"error: {exc}")

    def on_quick_assemble(self, call_now: bool) -> None:
        try:
            name = self.quick_name.get().strip()
            if not re.fullmatch(r"[A-Za-z_][\w.]*", name):
                raise ValueError("code name must be letters/digits/_ (start with a letter), e.g. code0")
            clash = find_buffer(self.state, name)
            if clash and clash.note != "code":
                raise ValueError(f"@{name} is a normal buffer - pick another code name (press New)")
            pid = self._pid()
            prot_map = {"rx": PROT_READ | PROT_EXEC, "rwx": PROT_READ | PROT_WRITE | PROT_EXEC}
            prot = prot_map[self.quick_prot.get()]
            code = self.quick_asm.get("1.0", "end-1c")
            auto_ret = self.quick_auto_ret.get()
            auto_frame = self.quick_auto_frame.get()
            raw_args = {reg: (self.arg_kind[reg].get(), self.arg_val[reg].get()) for reg in REGS}
            vars_text = self.quick_vars.get()
            prot_name = self.quick_prot.get()
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            # Same expression engine as cheats: @buf, module(x), $var, [ptr], + - *
            rt = Runtime(self.client, self.state, pid, RemoteBuffer, lambda m: None, [])
            try:
                rt.vars["ret"] = self.state.last_rax & 0xFFFFFFFFFFFFFFFF
                self._parse_quick_vars(vars_text, rt.ev, rt.vars)
                resolved = asmgen.substitute(code, rt.ev)
                if auto_frame:
                    resolved = asmgen.auto_frame(resolved)[0]
                resolved = asmgen.ensure_ret(resolved, auto_ret)
                raw = asmgen.assemble(resolved)
                data = asmgen.pad(raw, None)
            except Exception as exc:
                msg = f"error: {exc}"
                self.root.after(0, lambda: self.quick_out.set(msg))
                return
            old = find_buffer(self.state, name)
            if old and old.size >= len(data):
                addr, size = old.address, old.size  # update in place: pointer stays the same
                self.client.protect(pid, addr, size, PROT_READ | PROT_WRITE | PROT_EXEC)
            else:
                if old:
                    self.client.free(pid, old.address, old.size)
                    self.state.buffers.remove(old)
                size = max(0x100, (len(data) + 0xFF) & ~0xFF)  # headroom so edits can reuse it
                addr = self.client.alloc(pid, size)
                self.state.buffers.append(RemoteBuffer(name, addr, size, "code"))
            self.client.write(pid, addr, data)
            self.client.protect(pid, addr, size, prot)
            self.code_sources[name] = {
                "asm": code, "auto_ret": auto_ret, "auto_frame": auto_frame, "prot": prot_name,
                "vars": {n: (e, rt.vars.get(n, 0)) for n, e in self._split_quick_vars(vars_text)},
            }
            if call_now:
                rax = self.client.call(pid, addr, **{
                    reg: encode_arg(kind, text, self.state) for reg, (kind, text) in raw_args.items()
                })
                self.state.last_rax = rax
            self.root.after(0, lambda: self._after_quick_assemble(name, addr, len(raw), len(data), call_now))

        self._run_bg(work, "Assembling & writing..." if not call_now else "Assembling & calling...")

    def _after_quick_assemble(self, name: str, addr: int, raw_len: int, padded_len: int, called: bool) -> None:
        self._refresh_buf_tree()
        self.rip_var.set(f"@{name}")
        self.quick_out.set(f"{raw_len} bytes written to @{name} 0x{addr:X} (padded to {padded_len})"
                           + (f"  ->  RAX = 0x{self.state.last_rax:X}" if called else ""))
        self.log_line(f"quick code @{name}: {raw_len} bytes @ 0x{addr:X}" + (f", called -> rax=0x{self.state.last_rax:X}"
                                                                     if called else ", set as RIP"))

    def _selected_buffer(self) -> RemoteBuffer:
        sel = self.buf_tree.selection()
        if not sel:
            raise ValueError("select a buffer first")
        name = self.buf_tree.item(sel[0], "values")[0]
        buf = find_buffer(self.state, name)
        if buf is None:
            raise ValueError("buffer missing from list")
        return buf

    def _code_names(self) -> list[str]:
        return [b.name for b in self.state.buffers if b.note == "code"]

    def on_quick_new_name(self) -> None:
        used = {b.name for b in self.state.buffers}
        n = 0
        while f"code{n}" in used:
            n += 1
        self.quick_name.set(f"code{n}")
        self.quick_out.set(f"new code buffer name: code{n}  (assemble to create it)")

    def _refresh_buf_tree(self) -> None:
        if hasattr(self, "quick_name_combo"):
            self.quick_name_combo.configure(values=self._code_names())
        self.buf_tree.delete(*self.buf_tree.get_children())
        for buf in self.state.buffers:
            self.buf_tree.insert("", "end", values=(buf.name, f"0x{buf.address:X}", buf.size))

    def on_alloc(self) -> None:
        try:
            pid = self._pid()
            name = self.buf_name.get().strip()
            if not name:
                raise ValueError("buffer needs a name")
            if find_buffer(self.state, name):
                raise ValueError(f"buffer {name} already exists")
            size = parse_int(self.buf_size.get(), self.state)
            if size <= 0:
                raise ValueError("size must be > 0")
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            addr = self.client.alloc(pid, size)
            self.state.buffers.append(RemoteBuffer(name, addr, size))
            self.root.after(0, lambda: self._after_alloc(name, addr, size))

        self._run_bg(work, "Allocating...")

    def _after_alloc(self, name, addr, size) -> None:
        self._refresh_buf_tree()
        self.deref_addr.set(f"@{name}")
        self.hex_addr.set(f"0x{addr:X}")
        self.log_line(f"alloc {name}  0x{addr:X}  {size} bytes")
        n = name
        if n.startswith("buf") and n[3:].isdigit():
            self.buf_name.set(f"buf{int(n[3:]) + 1}")

    def on_free(self) -> None:
        try:
            buf = self._selected_buffer()
            pid = self._pid()
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            self.client.free(pid, buf.address, buf.size)
            self.state.buffers = [b for b in self.state.buffers if b.name != buf.name]
            self.root.after(0, lambda: self._after_free(buf))

        self._run_bg(work, "Freeing...")

    def _after_free(self, buf: RemoteBuffer) -> None:
        self._refresh_buf_tree()
        self.log_line(f"freed {buf.name}  0x{buf.address:X}")

    def on_protect(self, prot: int) -> None:
        try:
            buf = self._selected_buffer()
            pid = self._pid()
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            self.client.protect(pid, buf.address, buf.size, prot)
            self.root.after(0, lambda: self.log_line(f"protect {buf.name} prot={prot}"))

        self._run_bg(work, "Protect...")

    def on_copy_ptr(self) -> None:
        try:
            buf = self._selected_buffer()
        except Exception as exc:
            self._fail(exc)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(f"0x{buf.address:X}")
        self.log_line(f"copied pointer 0x{buf.address:X}")

    def _use_buf_as(self, reg: str) -> None:
        try:
            buf = self._selected_buffer()
        except Exception as exc:
            self._fail(exc)
            return
        self.arg_kind[reg].set("u64 / pointer")
        self.arg_val[reg].set(f"@{buf.name}")
        self.log_line(f"{reg} = @{buf.name} (0x{buf.address:X})")

    def on_write_buf(self) -> None:
        try:
            buf = self._selected_buffer()
            data = build_payload(
                self.payload_kind.get(),
                self.payload_text.get("1.0", "end-1c"),
                self.add_nul.get(),
            )
            if len(data) > buf.size:
                raise ValueError(f"payload {len(data)} bytes does not fit in {buf.size}")
            pid = self._pid()
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            self.client.write(pid, buf.address, data)
            self.root.after(
                0, lambda: self.log_line(f"wrote {len(data)} bytes to {buf.name} @ 0x{buf.address:X}")
            )

        self._run_bg(work, "Writing buffer...")

    def _resolve_deref_base(self, pid: int, addr: int, follow: int, offset: int) -> int:
        for _ in range(follow):
            raw = self.client.read(pid, addr, 8)
            addr = struct.unpack("<Q", raw)[0]
        return (addr + offset) & 0xFFFFFFFFFFFFFFFF

    def _deref_read_len(self) -> int:
        kind = self.deref_kind.get()
        sizes = {
            "u8": 1,
            "i8": 1,
            "u16": 2,
            "i16": 2,
            "u32": 4,
            "i32": 4,
            "u64 / pointer": 8,
            "i64": 8,
            "float": 4,
            "double": 8,
            "cstring": int(self.deref_len.get() or "64", 0),
            "utf-16le string": int(self.deref_len.get() or "128", 0),
            "hex dump": int(self.deref_len.get() or "64", 0),
        }
        n = sizes[kind]
        if n <= 0:
            raise ValueError("length must be > 0")
        return n

    def on_deref(self) -> None:
        try:
            pid = self._pid()
            kind = self.deref_kind.get()
            n = self._deref_read_len()
            start = parse_int(self.deref_addr.get(), self.state)
            follow = int(self.follow_n.get().strip() or "0", 0)
            offset = parse_int(self.deref_off.get(), self.state)
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            addr = self._resolve_deref_base(pid, start, follow, offset)
            data = self.client.read(pid, addr, n)
            text = decode_value(kind, data)
            self.root.after(0, lambda: self._show_deref(addr, data, text))

        self._run_bg(work, "Reading...")

    def _show_deref(self, addr: int, data: bytes, text: str) -> None:
        self.deref_out.delete("1.0", "end")
        self.deref_out.insert("end", f"addr 0x{addr:X}  {len(data)} bytes\n{text}\n")
        self.log_line(f"deref 0x{addr:X}: {text.splitlines()[0]}")
        if self.deref_kind.get() == "u64 / pointer" and len(data) >= 8:
            self.write_val.set(f"0x{struct.unpack('<Q', data[:8])[0]:X}")

    def _use_deref_as(self, reg: str) -> None:
        text = self.write_val.get().strip() or self.deref_out.get("1.0", "end")
        if "0x" in text:
            token = text[text.find("0x") :].split()[0]
        else:
            token = self.deref_addr.get()
        self.arg_kind[reg].set("u64 / pointer")
        self.arg_val[reg].set(token)
        self.log_line(f"{reg} = {token}")

    def on_write_primitive(self) -> None:
        try:
            pid = self._pid()
            kind = self.deref_kind.get()
            text = self.write_val.get().strip()
            if kind in ("cstring", "utf-16le string", "hex dump"):
                raise ValueError("use the buffer writer for strings / hex")
            start = parse_int(self.deref_addr.get(), self.state)
            follow = int(self.follow_n.get().strip() or "0", 0)
            offset = parse_int(self.deref_off.get(), self.state)
            if kind == "float":
                data = struct.pack("<f", float(text))
            elif kind == "double":
                data = struct.pack("<d", float(text))
            else:
                value = parse_int(text, self.state)
                widths = {
                    "u8": 1,
                    "i8": 1,
                    "u16": 2,
                    "i16": 2,
                    "u32": 4,
                    "i32": 4,
                    "u64 / pointer": 8,
                    "i64": 8,
                }
                width = widths[kind]
                data = (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            addr = self._resolve_deref_base(pid, start, follow, offset)
            self.client.write(pid, addr, data)
            self.root.after(0, lambda: self.log_line(f"wrote {kind} to 0x{addr:X}"))

        self._run_bg(work, "Writing...")

    def _update_hex_status(self) -> None:
        view = self.hex_view
        if view.empty():
            self.hex_status.set("No data loaded")
            return
        addr = view.cursor_addr()
        dirty = view.dirty_count()
        parts = [f"cursor 0x{addr:X}", f"+{view.cursor:X}", f"{len(view.data)} bytes"]
        for label, size in (("u8", 1), ("u16", 2), ("u32", 4), ("u64", 8)):
            val = view.value_at_cursor(size)
            if val is None:
                continue
            parts.append(f"{label}=0x{val:X}")
        ch = view.data[view.cursor]
        ascii_ch = chr(ch) if 32 <= ch < 127 else "."
        parts.append(f"ascii={ascii_ch}")
        sel = view.selection_range()
        if sel:
            lo, hi = sel
            parts.insert(1, f"SELECTED {hi - lo + 1} bytes (0x{view.base + lo:X}-0x{view.base + hi:X})")
        if dirty:
            parts.append(f"{dirty} modified")
        self.hex_status.set("   ".join(parts))

    def on_dump_region(self) -> None:
        """Read a (possibly large) range from the console straight into a file."""
        try:
            pid = self._pid()
        except Exception as exc:
            self._fail(exc)
            return
        start_default = f"0x{self.hex_view.cursor_addr():X}" if not self.hex_view.empty() else self.hex_addr.get()
        a_txt = simpledialog.askstring("Dump region", "Start address (0x..., @buf, rax):",
                                       initialvalue=start_default, parent=self.root)
        if not a_txt:
            return
        l_txt = simpledialog.askstring("Dump region", "Length in bytes (e.g. 0x10000):",
                                       initialvalue="0x10000", parent=self.root)
        if not l_txt:
            return
        try:
            start = self.eval_int(a_txt)
            length = self.eval_int(l_txt)
            if length <= 0:
                raise ValueError("length must be > 0")
        except Exception as exc:
            self._fail(exc)
            return
        if length > 0x4000000 and not messagebox.askyesno(
            "Dump region", f"That is {length / 1048576:.0f} MB - continue?"
        ):
            return
        path = filedialog.asksaveasfilename(
            title="Save dump as", defaultextension=".bin", initialfile=f"dump_{start:X}_{length:X}.bin",
            filetypes=[("Raw binary", "*.bin"), ("All files", "*.*")],
        )
        if not path:
            return

        def work() -> None:
            done = 0
            try:
                with open(path, "wb") as fh:
                    while done < length:
                        n = min(0x10000, length - done)
                        fh.write(self.client.read(pid, (start + done) & 0xFFFFFFFFFFFFFFFF, n))
                        done += n
                        if done % 0x100000 == 0:
                            self.root.after(0, lambda d=done: self.log_line(f"  dumped {d:#x} / {length:#x} bytes"))
            except Exception as exc:
                raise RuntimeError(
                    f"dump stopped after {done:#x} of {length:#x} bytes at 0x{start + done:X}: {exc} "
                    f"(partial file kept: {path})"
                ) from exc
            self.root.after(0, lambda: self.log_line(f"dumped {length:#x} bytes from 0x{start:X} to {path}"))

        self._run_bg(work, "Dumping memory...")

    def _hex_goto_value(self, addr: int, length: Optional[int] = None) -> None:
        self.hex_addr.set(f"0x{addr:X}")
        if length is not None:
            self.hex_len.set(str(length))
        self.notebook.select(self._hex_tab)
        self.on_hex_go()

    def _hex_goto_field(self, var: tk.StringVar) -> None:
        try:
            addr = parse_int(var.get(), self.state)
        except Exception as exc:
            self._fail(exc)
            return
        self._hex_goto_value(addr)

    def on_buf_open_hex(self) -> None:
        try:
            buf = self._selected_buffer()
        except Exception as exc:
            self._fail(exc)
            return
        self._hex_goto_value(buf.address, min(buf.size, 4096))

    def on_deref_open_hex(self) -> None:
        try:
            addr = parse_int(self.deref_addr.get(), self.state)
        except Exception as exc:
            self._fail(exc)
            return
        self._hex_goto_value(addr)

    def on_hex_page(self, direction: int) -> None:
        try:
            length = int(self.hex_len.get().strip() or "256", 0)
            if length <= 0:
                raise ValueError("bytes must be > 0")
            if self.hex_view.empty():
                addr = parse_int(self.hex_addr.get(), self.state)
            else:
                addr = self.hex_view.base + direction * length
            if addr < 0:
                addr = 0
        except Exception as exc:
            self._fail(exc)
            return
        self.hex_addr.set(f"0x{addr:X}")
        self.on_hex_go()

    def on_hex_go(self) -> None:
        try:
            pid = self._pid()
            addr = parse_int(self.hex_addr.get(), self.state)
            length = int(self.hex_len.get().strip() or "256", 0)
            if length <= 0:
                raise ValueError("bytes must be > 0")
            if length > 65536:
                raise ValueError("max 65536 bytes per view")
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            data = self.client.read(pid, addr, length)
            self.root.after(0, lambda: self._show_hex(addr, data))

        self._run_bg(work, "Reading hex...")

    def _show_hex(self, addr: int, data: bytes) -> None:
        self.notebook.select(self._hex_tab)
        self.hex_addr.set(f"0x{addr:X}")
        self.hex_view.set_data(addr, data)
        self.log_line(f"hex 0x{addr:X}  {len(data)} bytes")

    def on_hex_revert(self) -> None:
        self.hex_view.revert()
        self._update_hex_status()
        self.log_line("hex edits reverted (not written)")

    def on_hex_write(self) -> None:
        try:
            pid = self._pid()
            patches = self.hex_view.patches()
            if not patches:
                raise ValueError("no modified bytes to write")
            base = self.hex_view.base
            view_len = len(self.hex_view.data)
        except Exception as exc:
            self._fail(exc)
            return

        def work() -> None:
            total = 0
            for addr, blob in patches:
                self.client.write(pid, addr, blob)
                total += len(blob)
            data = self.client.read(pid, base, view_len)
            n = total
            self.root.after(0, lambda: self._after_hex_write(data, n))

        self._run_bg(work, "Writing hex...")

    def _after_hex_write(self, data: bytes, total: int) -> None:
        self.hex_view.set_data(self.hex_view.base, data)
        self.log_line(f"wrote {total} modified byte(s) at 0x{self.hex_view.base:X}")

    def on_hex_use_rdi(self) -> None:
        if self.hex_view.empty():
            self._fail(ValueError("load a hex view first"))
            return
        addr = self.hex_view.cursor_addr()
        self.arg_kind["rdi"].set("u64 / pointer")
        self.arg_val["rdi"].set(f"0x{addr:X}")
        self.log_line(f"rdi = 0x{addr:X}")
        self.notebook.select(self._caller_tab)


def main() -> None:
    if sys.platform == "win32":
        try:  # sharp text on high-DPI screens (must happen before the window exists)
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    settings = load_settings()
    if sys.platform == "win32":
        try:  # own taskbar button + icon instead of python.exe's
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ps5debug.toolkit")
        except Exception:
            pass
    root = tk.Tk()
    from app_paths import set_window_icon
    set_window_icon(root)
    theme.apply(root, settings.get("theme", "light"))
    FunctionCallerApp(root, settings)
    root.mainloop()


if __name__ == "__main__":
    main()