"""Scanner tab - Cheat Engine style memory scanner on ps5debug-NG Turbo Scan.

Layout (like CE): found-address list on the left, scan controls on the
right, the address list ("cheat table") at the bottom.

How it talks to the console
  * The scan runs on its OWN connection (TurboScanSession): the server keeps
    the survivors there (server-resident list / snapshot), so a first scan
    over gigabytes only sends a count back, and Next Scan narrows in place.
    A running scan blocks only that socket - the rest of the app keeps working.
  * A second "aux" connection reads live values for the visible rows (one
    bulk-read per refresh), writes frozen values (one bulk-write per tick)
    and sends Cancel (the protocol requires cancel on another connection).
"""

from __future__ import annotations

import json
import queue
import struct
import threading
import time
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path

from app_paths import APP_DIR
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Callable, Optional

import theme
from scrollable import ScrollFrame
from ps5debug_client import (
    PS5DebugClient, ProtocolError, TurboCaps, TurboScanSession,
    TS_FLOAT_EXACT, TS_FLOAT_SIMPLE, TS_RESCAN_ALIASING, TS_USE_ALIASING,
    TSE_ALIASING, TSE_FLOAT_POLICY, TSE_RESCAN_ALIASING,
)

# ---------------------------------------------------------------------------
# value types
# ---------------------------------------------------------------------------
# label -> (unsigned type id, signed type id, size)
VALUE_TYPES: dict[str, tuple[int, int, int]] = {
    "Byte": (0, 1, 1),
    "2 Bytes": (2, 3, 2),
    "4 Bytes": (4, 5, 4),
    "8 Bytes": (6, 7, 8),
    "Float": (8, 8, 4),
    "Double": (9, 9, 8),
    "String": (10, 10, 0),
    "Array of bytes": (10, 10, 0),
}
FMT = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<Q", 7: "<q", 8: "<f", 9: "<d"}

FIRST_SCANS = [("Exact value", 0), ("Bigger than...", 2), ("Smaller than...", 3),
               ("Value between...", 4), ("Unknown initial value", 11)]
NEXT_SCANS = [("Exact value", 0), ("Bigger than...", 2), ("Smaller than...", 3), ("Value between...", 4),
              ("Increased value", 5), ("Increased value by...", 6), ("Decreased value", 7),
              ("Decreased value by...", 8), ("Changed value", 9), ("Unchanged value", 10)]
FUZZY = ("Rounded (±1)", 1)
NO_VALUE = {5, 7, 9, 10, 11}
PAGE = 1000


@dataclass
class TypeSpec:
    label: str
    tid: int
    size: int
    hex: bool = False
    utf16: bool = False

    @property
    def is_float(self) -> bool:
        return self.tid in (8, 9)

    @property
    def is_int(self) -> bool:
        return self.tid <= 7

    def encode(self, text: str) -> tuple[bytes, Optional[bytes]]:
        """-> (value bytes, mask or None)"""
        t = text.strip()
        if self.label == "Array of bytes":
            pat, mask = bytearray(), bytearray()
            toks = t.replace(",", " ").split()
            if len(toks) == 1 and len(toks[0]) > 2 and "?" not in toks[0]:
                h = toks[0]
                toks = [h[i:i + 2] for i in range(0, len(h), 2)]
            for tok in toks:
                if tok in ("?", "??", "*", "**"):
                    pat.append(0)
                    mask.append(0)
                else:
                    pat.append(int(tok, 16) & 0xFF)
                    mask.append(1)
            if not pat:
                raise ValueError("type the bytes, e.g. 48 8B ?? 05")
            return bytes(pat), bytes(mask)
        if self.label == "String":
            if not text:
                raise ValueError("type the text to search for")
            data = text.encode("utf-16le" if self.utf16 else "utf-8")
            return data, b"\x01" * len(data)
        if not t:
            raise ValueError("type a value")
        if self.is_float:
            return struct.pack(FMT[self.tid], float(t)), None
        v = int(t, 16) if self.hex and not t.lower().startswith(("0x", "-")) else int(t, 0)
        bits = 8 * self.size
        if v < 0:
            v &= (1 << bits) - 1
        if v >= 1 << bits:
            raise ValueError(f"{t} does not fit in {self.label}")
        return v.to_bytes(self.size, "little"), None

    def decode(self, data: bytes) -> str:
        if not data:
            return "??"
        if self.label == "Array of bytes":
            return data.hex(" ").upper()
        if self.label == "String":
            return data.decode("utf-16le" if self.utf16 else "utf-8", "replace").replace("\x00", "·")
        if len(data) < self.size:
            return "??"
        v = struct.unpack(FMT[self.tid], data[: self.size])[0]
        if self.is_float:
            return f"{v:.6g}"
        if self.hex:
            return f"{v & ((1 << (8 * self.size)) - 1):X}"
        return str(v)

    def to_dict(self) -> dict:
        return {"label": self.label, "tid": self.tid, "size": self.size, "hex": self.hex, "utf16": self.utf16}

    @staticmethod
    def from_dict(d: dict) -> "TypeSpec":
        return TypeSpec(d["label"], int(d["tid"]), int(d["size"]), bool(d.get("hex")), bool(d.get("utf16")))


@dataclass
class Entry:
    """A row of the address list (cheat table)."""
    desc: str
    addr: int
    spec: TypeSpec
    frozen: bool = False
    freeze_data: bytes = b""
    value: str = "?"
    iid: str = ""
    chain: Optional[object] = None      # pointer_scan.Chain: the address is re-followed live


# ---------------------------------------------------------------------------
class ScannerTab:
    def __init__(self, parent: ttk.Frame, app) -> None:
        self.app = app
        self.root = app.root
        self.scan_cli: Optional[PS5DebugClient] = None
        self.aux_cli: Optional[PS5DebugClient] = None
        self.aux_lock = threading.Lock()
        self.caps: Optional[TurboCaps] = None
        self.session: Optional[TurboScanSession] = None
        self.scan_spec: Optional[TypeSpec] = None
        self.scan_pid = 0
        self.scanning = False
        self.scan_no = 0
        self.scan_align = 1
        # undo: after each scan the result addresses are kept here (small scans only, so scanning
        # stays fast); going back re-reads just those addresses on the console
        self.history: list[dict] = []
        self.page = 0
        self.rows: list = []            # ScanResult for the current page
        self.entries: list[Entry] = []
        self._ui_q: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self._live_values: dict[int, bytes] = {}
        self._stop = threading.Event()
        self._build(parent)
        self._sync_scan_types()
        self.root.after(40, self._drain)
        threading.Thread(target=self._live_loop, daemon=True, name="scanner-live").start()
        threading.Thread(target=self._freeze_loop, daemon=True, name="scanner-freeze").start()

    # ================================================================ UI
    def _build(self, parent: ttk.Frame) -> None:
        pw = ttk.Panedwindow(parent, orient="vertical")
        pw.pack(fill="both", expand=True, padx=8, pady=8)
        top = ttk.Frame(pw)
        bottom = ttk.Frame(pw)
        pw.add(top, weight=3)
        pw.add(bottom, weight=2)

        # ---- found list (left)
        left = ttk.Frame(top)
        left.pack(side="left", fill="both", expand=True)
        head = ttk.Frame(left)
        head.pack(fill="x")
        self.found_var = tk.StringVar(value="Found: 0")
        ttk.Label(head, textvariable=self.found_var, style="Title.TLabel").pack(side="left")
        self.page_var = tk.StringVar(value="")
        ttk.Button(head, text="▶", width=3, style="Small.TButton",
                   command=lambda: self._goto_page(self.page + 1)).pack(side="right")
        ttk.Label(head, textvariable=self.page_var, style="Muted.TLabel").pack(side="right", padx=6)
        ttk.Button(head, text="◀", width=3, style="Small.TButton",
                   command=lambda: self._goto_page(self.page - 1)).pack(side="right")

        tf = ttk.Frame(left)
        tf.pack(fill="both", expand=True, pady=(4, 0))
        cols = ("addr", "value", "prev", "first")
        self.res = ttk.Treeview(tf, columns=cols, show="headings", selectmode="extended")
        for col, text, w, anchor in (("addr", "Address", 170, "w"), ("value", "Value", 130, "e"),
                                     ("prev", "Previous", 120, "e"), ("first", "First", 120, "e")):
            self.res.heading(col, text=text, anchor=anchor)
            self.res.column(col, width=w, anchor=anchor, stretch=True)
        theme.stripe(self.res)
        self.res.tag_configure("chg", foreground=theme.c("changed"))
        ys = ttk.Scrollbar(tf, orient="vertical", command=self.res.yview)
        self.res.configure(yscrollcommand=ys.set)
        self.res.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.res.bind("<Double-1>", lambda _e: self.add_selected_results())
        self.res.bind("<Return>", lambda _e: self.add_selected_results())
        self.res.bind("<Button-3>", self._res_menu)
        self.res.bind("<Control-c>", lambda _e: self._copy_res_addr())

        # ---- controls (right) - scrolls when the window is too short for all the options
        rs = ScrollFrame(top, horizontal=False)
        rs.pack(side="right", fill="y", padx=(12, 0))
        right = rs.body
        right.bind("<Configure>", lambda _e: rs.canvas.configure(width=right.winfo_reqwidth()), add="+")
        self._ctl_scroll = rs

        btns = ttk.Frame(right)
        btns.pack(fill="x")
        self.first_btn = ttk.Button(btns, text="First Scan", style="Accent.TButton", command=self.on_first)
        self.first_btn.pack(side="left", fill="x", expand=True)
        self.next_btn = ttk.Button(btns, text="Next Scan", command=self.on_next, state="disabled")
        self.next_btn.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.cancel_btn = ttk.Button(right, text="Cancel scan", style="Danger.TButton", command=self.on_cancel)
        hrow = ttk.Frame(right)
        hrow.pack(fill="x", pady=(6, 0))
        self.undo_btn = ttk.Button(hrow, text="↶ Undo scan", style="Small.TButton", command=self.on_undo,
                                   state="disabled")
        self.undo_btn.pack(side="left")
        self.hist_var = tk.StringVar(value="")
        self.hist_cb = ttk.Combobox(hrow, textvariable=self.hist_var, state="disabled", width=26)
        self.hist_cb.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.hist_cb.bind("<<ComboboxSelected>>", lambda _e: self.on_history_pick())
        self.progress = ttk.Progressbar(right, mode="determinate", maximum=1000)
        self.progress.pack(fill="x", pady=(8, 2))
        self.status_var = tk.StringVar(value="Pick a process, type a value, press First Scan.")
        ttk.Label(right, textvariable=self.status_var, style="Muted.TLabel", wraplength=320,
                  justify="left").pack(fill="x")

        vf = ttk.Frame(right)
        vf.pack(fill="x", pady=(10, 0))
        ttk.Label(vf, text="Value").grid(row=0, column=0, sticky="w")
        self.hex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(vf, text="Hex", variable=self.hex_var).grid(row=0, column=1, sticky="e")
        self.value_var = tk.StringVar()
        self.value_entry = ttk.Entry(vf, textvariable=self.value_var, width=34, font=theme.mono(11))
        self.value_entry.grid(row=1, column=0, columnspan=2, sticky="we", pady=(2, 0))
        self.value_entry.bind("<Return>", lambda _e: self.on_next() if self._can_next() else self.on_first())
        self.to_lbl = ttk.Label(vf, text="and")
        self.value2_var = tk.StringVar()
        self.value2_entry = ttk.Entry(vf, textvariable=self.value2_var, width=34, font=theme.mono(11))
        vf.columnconfigure(0, weight=1)

        g = ttk.Frame(right)
        g.pack(fill="x", pady=(8, 0))
        ttk.Label(g, text="Scan type").grid(row=0, column=0, sticky="w", pady=2)
        self.scan_type_var = tk.StringVar()
        self.scan_type_cb = ttk.Combobox(g, textvariable=self.scan_type_var, state="readonly", width=24)
        self.scan_type_cb.grid(row=0, column=1, sticky="we", padx=(8, 0), pady=2)
        self.scan_type_cb.bind("<<ComboboxSelected>>", lambda _e: self._sync_value_fields())
        ttk.Label(g, text="Value type").grid(row=1, column=0, sticky="w", pady=2)
        self.vtype_var = tk.StringVar(value="4 Bytes")
        self.vtype_cb = ttk.Combobox(g, textvariable=self.vtype_var, values=list(VALUE_TYPES),
                                     state="readonly", width=24)
        self.vtype_cb.grid(row=1, column=1, sticky="we", padx=(8, 0), pady=2)
        self.vtype_cb.bind("<<ComboboxSelected>>", lambda _e: self._on_vtype())
        g.columnconfigure(1, weight=1)

        self.signed_var = tk.BooleanVar(value=False)
        self.utf16_var = tk.BooleanVar(value=False)
        self.opt_row = ttk.Frame(right)
        self.opt_row.pack(fill="x", pady=(4, 0))
        self.signed_cb = ttk.Checkbutton(self.opt_row, text="Signed", variable=self.signed_var)
        self.utf16_cb = ttk.Checkbutton(self.opt_row, text="UTF-16", variable=self.utf16_var)
        self.float_exact_var = tk.BooleanVar(value=False)
        self.float_simple_var = tk.BooleanVar(value=False)
        self.fexact_cb = ttk.Checkbutton(self.opt_row, text="Exact float compare",
                                         variable=self.float_exact_var)
        self.fsimple_cb = ttk.Checkbutton(self.opt_row, text="Simple values only",
                                          variable=self.float_simple_var)

        mo = ttk.LabelFrame(right, text="MEMORY SCAN OPTIONS", padding=8)
        mo.pack(fill="x", pady=(12, 0))
        r = 0
        ttk.Label(mo, text="Start").grid(row=r, column=0, sticky="w")
        self.start_var = tk.StringVar(value="0")
        ttk.Entry(mo, textvariable=self.start_var, width=20, font=theme.mono()).grid(row=r, column=1, sticky="we",
                                                                                     padx=(6, 0), pady=1)
        r += 1
        ttk.Label(mo, text="Stop").grid(row=r, column=0, sticky="w")
        self.stop_var = tk.StringVar(value="7FFFFFFFFFFF")
        ttk.Entry(mo, textvariable=self.stop_var, width=20, font=theme.mono()).grid(row=r, column=1, sticky="we",
                                                                                    padx=(6, 0), pady=1)
        r += 1
        self.writable_var = tk.BooleanVar(value=True)
        self.exec_var = tk.BooleanVar(value=False)
        self.skip_slow_var = tk.BooleanVar(value=False)
        self.fast_var = tk.BooleanVar(value=True)
        self.align_var = tk.StringVar(value="4")
        self.zeros_var = tk.BooleanVar(value=False)
        self.alias_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(mo, text="Writable memory only", variable=self.writable_var).grid(
            row=r, column=0, columnspan=2, sticky="w", pady=(4, 0))
        r += 1
        ttk.Checkbutton(mo, text="Include executable (code) regions", variable=self.exec_var).grid(
            row=r, column=0, columnspan=2, sticky="w")
        r += 1
        ttk.Checkbutton(mo, text="Skip slow / uncached regions (GPU)", variable=self.skip_slow_var).grid(
            row=r, column=0, columnspan=2, sticky="w")
        r += 1
        fr = ttk.Frame(mo)
        fr.grid(row=r, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(fr, text="Fast scan, alignment", variable=self.fast_var).pack(side="left")
        ttk.Entry(fr, textvariable=self.align_var, width=4).pack(side="left", padx=4)
        r += 1
        ttk.Checkbutton(mo, text="Unknown value: include zeros (slower)", variable=self.zeros_var).grid(
            row=r, column=0, columnspan=2, sticky="w")
        r += 1
        self.alias_cb = ttk.Checkbutton(mo, text="Fast read engine (aliasing)", variable=self.alias_var)
        self.alias_cb.grid(row=r, column=0, columnspan=2, sticky="w")
        mo.columnconfigure(1, weight=1)

        self.caps_var = tk.StringVar(value="")
        ttk.Label(right, textvariable=self.caps_var, style="Muted.TLabel", wraplength=300,
                  justify="left").pack(fill="x", side="bottom")

        # ---- address list (bottom)
        bar = ttk.Frame(bottom)
        bar.pack(fill="x", pady=(6, 4))
        ttk.Label(bar, text="Address list", style="Title.TLabel").pack(side="left")
        for text, cmd in (("Pointer scan…", lambda: self.open_pointer_scan()),
                          ("Add address…", self.on_add_manual), ("Delete", self.on_delete_entries),
                          ("Load table…", self.on_load_table), ("Save table…", self.on_save_table),
                          ("Copy as cheat JSON", self.on_copy_cheat)):
            ttk.Button(bar, text=text, style="Small.TButton", command=cmd).pack(side="right", padx=(4, 0))
        lf = ttk.Frame(bottom)
        lf.pack(fill="both", expand=True)
        cols = ("frz", "desc", "addr", "type", "value")
        self.lst = ttk.Treeview(lf, columns=cols, show="headings", selectmode="extended", height=6)
        for col, text, w, anchor, st in (("frz", "Active", 60, "center", False), ("desc", "Description", 260, "w", True),
                                         ("addr", "Address", 170, "w", False), ("type", "Type", 110, "w", False),
                                         ("value", "Value", 200, "w", True)):
            self.lst.heading(col, text=text, anchor=anchor)
            self.lst.column(col, width=w, anchor=anchor, stretch=st)
        theme.stripe(self.lst)
        self.lst.tag_configure("frozen", foreground=theme.c("frozen"))
        ys2 = ttk.Scrollbar(lf, orient="vertical", command=self.lst.yview)
        self.lst.configure(yscrollcommand=ys2.set)
        self.lst.pack(side="left", fill="both", expand=True)
        ys2.pack(side="right", fill="y")
        self.lst.bind("<Double-1>", self._lst_double)
        self.lst.bind("<space>", lambda _e: self.toggle_freeze())
        self.lst.bind("<Delete>", lambda _e: self.on_delete_entries())
        self.lst.bind("<Button-1>", self._lst_click, add="+")
        self.lst.bind("<Button-3>", self._lst_menu)
        ttk.Label(bottom, style="Muted.TLabel",
                  text="Double-click a result to add it here.  Click Active (or Space) to freeze.  "
                       "Double-click Description / Value to edit.  Right-click for more.").pack(anchor="w", pady=(4, 0))

    # ------------------------------------------------------------- helpers
    def _post(self, fn: Callable[[], None]) -> None:
        self._ui_q.put(fn)

    def _drain(self) -> None:
        try:
            for _ in range(200):
                self._ui_q.get_nowait()()
        except queue.Empty:
            pass
        except Exception as exc:          # never let one bad callback stop the pump
            self.app.log_line(f"scanner: {exc}")
        self.root.after(40, self._drain)

    def _spec(self) -> TypeSpec:
        label = self.vtype_var.get()
        u, s, size = VALUE_TYPES[label]
        tid = s if self.signed_var.get() else u
        return TypeSpec(label, tid, size, self.hex_var.get() and tid <= 7, self.utf16_var.get())

    def _can_next(self) -> bool:
        return bool(self.session and self.session.active and not self.scanning)

    def _scan_types(self) -> list[tuple[str, int]]:
        first = not self._can_next()
        label = self.vtype_var.get()
        if label in ("String", "Array of bytes"):
            return [("Exact value", 0)]
        types = list(FIRST_SCANS if first else NEXT_SCANS)
        if label in ("Float", "Double"):
            types.insert(1, FUZZY)
        return types

    def _scan_code(self) -> int:
        name = self.scan_type_var.get()
        for n, code in self._scan_types():
            if n == name:
                return code
        return 0

    def _sync_scan_types(self) -> None:
        types = self._scan_types()
        names = [n for n, _ in types]
        self.scan_type_cb.configure(values=names)
        if self.scan_type_var.get() not in names:
            self.scan_type_var.set(names[0])
        self._sync_value_fields()

    def _sync_value_fields(self) -> None:
        code = self._scan_code()
        state = "disabled" if code in NO_VALUE else "normal"
        self.value_entry.configure(state=state)
        if code == 4:
            self.to_lbl.grid(row=2, column=0, sticky="w", pady=(4, 0))
            self.value2_entry.grid(row=3, column=0, columnspan=2, sticky="we")
        else:
            self.to_lbl.grid_remove()
            self.value2_entry.grid_remove()

    def _on_vtype(self) -> None:
        label = self.vtype_var.get()
        for w in (self.signed_cb, self.utf16_cb, self.fexact_cb, self.fsimple_cb):
            w.pack_forget()
        if VALUE_TYPES[label][2] and label not in ("Float", "Double"):
            self.signed_cb.pack(side="left")
        if label == "String":
            self.utf16_cb.pack(side="left")
        if label in ("Float", "Double") and self.caps and self.caps.has(TSE_FLOAT_POLICY):
            self.fexact_cb.pack(side="left")
            self.fsimple_cb.pack(side="left", padx=(8, 0))
        size = VALUE_TYPES[label][2]
        self.align_var.set(str(size if size else 1))
        if not self._can_next():
            self._sync_scan_types()

    def _set_busy(self, busy: bool, label: str = "") -> None:
        self.scanning = busy
        if busy:
            self.first_btn.configure(state="disabled")
            self.next_btn.configure(state="disabled")
            self.cancel_btn.pack(fill="x", pady=(6, 0), after=self.first_btn.master)
            self.status_var.set(label)
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        else:
            self.cancel_btn.pack_forget()
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)
            self.first_btn.configure(state="normal",
                                     text="New Scan" if self.session and self.session.active else "First Scan")
            self.next_btn.configure(state="normal" if self._can_next() else "disabled")
            self.vtype_cb.configure(state="disabled" if self._can_next() else "readonly")
            self._sync_scan_types()
        self._sync_history()

    def _progress(self, phase: str, done: int, total: int) -> None:
        def ui() -> None:
            if total:
                if str(self.progress.cget("mode")) != "determinate":
                    self.progress.stop()
                    self.progress.configure(mode="determinate")
                self.progress.configure(value=min(1000, int(1000 * done / max(1, total))))
                self.status_var.set(f"{phase}: {100 * done / max(1, total):.0f}%")
            elif phase:
                self.status_var.set(phase)
        self._post(ui)

    # ---------------------------------------------------------- connections
    def _ensure_scan_conn(self) -> None:
        """Worker thread. Opens the scan connection + reads the server caps."""
        main = self.app.client
        if not main.connected:
            raise ProtocolError("connect to the console first")
        c = self.scan_cli
        if c is None or not c.connected or c.host != main.host:
            if c is not None:
                c.close()
            c = PS5DebugClient()
            c.connect(main.host, main.port)
            caps = c.turbo_caps()
            if caps is None:
                c.close()
                raise ProtocolError("this ps5debug payload has no Turbo Scan (needs ps5debug-NG 1.3.0 or newer)")
            c.auth()
            self.scan_cli, self.caps = c, caps
            self.session = TurboScanSession(c, caps)
            names = [n for bit, n in ((0x1, "SIMD"), (0x2, "aliasing"), (0x4, "resident"), (0x8, "snapshot"),
                                      (0x100, "parallel"), (0x400, "float policy")) if caps.engines & bit]
            self._post(lambda: (self.caps_var.set(
                f"Turbo Scan v{caps.version} · {caps.max_threads} threads · {', '.join(names)}"), self._on_vtype()))

    def _aux(self) -> Optional[PS5DebugClient]:
        """The helper connection (live values / freeze / cancel); None while disconnected."""
        main = self.app.client
        if not main.connected:
            if self.aux_cli is not None:
                self.aux_cli.close()
                self.aux_cli = None
            return None
        c = self.aux_cli
        if c is None or not c.connected or c.host != main.host:
            try:
                c = PS5DebugClient()
                c.connect(main.host, main.port, timeout=4.0)
                c.timeout = 10.0
                c.auth()
            except Exception:
                return None
            self.aux_cli = c
        return c

    def disconnect(self) -> None:
        """Main connection closed / changed console."""
        for c in (self.scan_cli, self.aux_cli):
            if c is not None:
                c.close()
        self.scan_cli = self.aux_cli = None
        if self.session:
            self.session.active = False
        self.session = None
        self.history = []
        self._post(lambda: (self._set_busy(False), self._show_page([])))

    # -------------------------------------------------------------- regions
    def _segments(self, cli: PS5DebugClient, pid: int) -> list[tuple[int, int]]:
        lo = int(self.start_var.get().strip() or "0", 16)
        hi = int(self.stop_var.get().strip() or "7FFFFFFFFFFF", 16)
        maps = cli.maps(pid)
        slow: set[int] = set()
        if self.skip_slow_var.get():
            try:
                for r in cli.turbo_regions(pid):
                    if r.uncached or (r.mbps and r.mbps < 100):
                        slow.add(r.start)
            except Exception as exc:
                self._post(lambda e=exc: self.app.log_line(f"scanner: region classify failed ({e}), scanning all"))
        regs: list[tuple[int, int]] = []
        for m in sorted(maps, key=lambda m: m.start):
            if not (m.prot & 1) or m.end <= m.start:
                continue
            if self.writable_var.get() and not (m.prot & 2):
                continue
            if not self.exec_var.get() and (m.prot & 4):
                continue
            if m.start in slow:
                continue
            a, b = max(m.start, lo), min(m.end, hi)
            if a >= b:
                continue
            if regs and regs[-1][0] + regs[-1][1] == a:          # merge touching regions
                regs[-1] = (regs[-1][0], regs[-1][1] + (b - a))
            else:
                regs.append((a, b - a))
        out: list[tuple[int, int]] = []
        piece = 0x40000000                                      # segment lengths are u32 on the wire
        for a, n in regs:
            while n > piece:
                out.append((a, piece))
                a, n = a + piece, n - piece
            out.append((a, n))
        return out

    def _flags(self, first: bool) -> int:
        f = 0
        caps = self.caps
        spec = self.scan_spec or self._spec()
        if caps and self.alias_var.get():
            if first and caps.has(TSE_ALIASING):
                f |= TS_USE_ALIASING
            if not first and caps.has(TSE_RESCAN_ALIASING):
                f |= TS_RESCAN_ALIASING
        if caps and caps.has(TSE_FLOAT_POLICY) and spec.is_float:
            if self.float_exact_var.get():
                f |= TS_FLOAT_EXACT
            if self.float_simple_var.get():
                f |= TS_FLOAT_SIMPLE
        return f

    def _value_bytes(self, spec: TypeSpec, code: int) -> tuple[bytes, Optional[bytes]]:
        if code in NO_VALUE:
            return b"", None
        v, mask = spec.encode(self.value_var.get())
        if code == 4:
            v2, _ = spec.encode(self.value2_var.get())
            v += v2
        return v, mask

    # ---------------------------------------------------------------- scans
    def on_first(self) -> None:
        if self.scanning:
            return
        if self.session and self.session.active:          # "New Scan"
            self._run(self._new_scan_work, "Clearing…")
            return
        try:
            pid = self.app._pid()
            spec = self._spec()
            code = self._scan_code()
            value, mask = self._value_bytes(spec, code)
            if spec.size == 0:
                spec.size = len(value)
            align = 1
            if self.fast_var.get():
                align = max(1, int(self.align_var.get().strip() or "1", 0))
            if align > 255:
                raise ValueError("alignment must be 1..255")
        except Exception as exc:
            self.app._fail(exc)
            return

        def work() -> None:
            self._ensure_scan_conn()
            segs = self._segments(self.scan_cli, pid)
            if not segs:
                raise ProtocolError("no memory region matches the scan options")
            self.scan_spec, self.scan_pid = spec, pid
            t0 = time.monotonic()
            n = self.session.first_scan(pid, segs, spec.tid, code, value, mask, align, self._flags(True),
                                        on_progress=self._progress, keep_first=True,
                                        include_zeros=self.zeros_var.get())
            self.scan_no = 1
            self.scan_align = align
            self.history = []
            self._record(n)
            dt = time.monotonic() - t0
            mb = sum(s for _a, s in segs) / 1048576
            self._after_scan(n, f"First scan: {n:,} result(s) in {dt:.1f}s · {mb:,.0f} MB in {len(segs)} region(s)")

        self._run(work, "First scan…")

    def on_next(self) -> None:
        if not self._can_next():
            return
        try:
            spec = self.scan_spec
            code = self._scan_code()
            value, mask = self._value_bytes(spec, code)
        except Exception as exc:
            self.app._fail(exc)
            return

        def work() -> None:
            t0 = time.monotonic()
            n = self.session.next_scan(code, value, mask, self._flags(False), on_progress=self._progress)
            self.scan_no += 1
            self._record(n)
            self._after_scan(n, f"Scan {self.scan_no}: {n:,} result(s) in {time.monotonic() - t0:.1f}s")

        self._run(work, "Next scan…")

    def _new_scan_work(self) -> None:
        try:
            if self.session and self.scan_cli and self.scan_cli.connected:
                self.session.end()
        finally:
            if self.session:
                self.session.active = False
            self.scan_no = 0
            self.history = []
            self._post(lambda: (self._show_page([]), self.status_var.set("New scan: pick the options, then First Scan."),
                                self.found_var.set("Found: 0")))

    def _after_scan(self, n: int, msg: str) -> None:
        rows = self.session.get(0, min(PAGE, n)) if n else []
        self.page = 0

        def ui() -> None:
            self.status_var.set(msg)
            self.app.log_line(f"scanner: {msg}")
            self._show_page(rows)
        self._post(ui)

    def _run(self, work: Callable[[], None], label: str) -> None:
        self._set_busy(True, label)

        def wrapper() -> None:
            try:
                work()
            except Exception as exc:
                msg = str(exc)
                self._post(lambda: (self.status_var.set(f"Error: {msg}"), self.app.log_line(f"scanner error: {msg}")))
                if self.scan_cli is not None and not self.scan_cli.connected:
                    self.scan_cli = None
                    if self.session:
                        self.session.active = False
            finally:
                self._post(lambda: self._set_busy(False))

        threading.Thread(target=wrapper, daemon=True, name="scanner-scan").start()

    # -------------------------------------------------------------- undo
    HIST_MAX = 1_000_000            # results kept per step (8 bytes each); bigger steps cannot be undone to

    def _record(self, n: int) -> None:
        """Remember this step's result addresses (scan thread)."""
        s = self.session
        entry = {"no": self.scan_no, "count": n, "addrs": None, "why": ""}
        if s.value_len > 8:
            entry["why"] = "byte arrays / text cannot be restored"
        elif n > self.HIST_MAX:
            entry["why"] = f"over {self.HIST_MAX:,} results"
        else:
            parts, start = [], 0
            while start < n:
                blob, got, rec = s.get_raw(start, min(262144, n - start))
                if not got:
                    break
                parts.append(b"".join(blob[i:i + 8] for i in range(0, got * rec, rec)))
                start += got
            entry["addrs"] = b"".join(parts)
        self.history.append(entry)

    @staticmethod
    def _hist_label(e: dict) -> str:
        return f"Scan {e['no']}: {e['count']:,} result(s)" + ("" if e["addrs"] is not None else f"  (no undo: {e['why']})")

    def _sync_history(self) -> None:
        h = self.history
        self.hist_cb.configure(values=[self._hist_label(e) for e in h],
                               state="readonly" if len(h) > 1 and not self.scanning else "disabled")
        self.hist_var.set(self._hist_label(h[-1]) if h else "")
        can = (not self.scanning and len(h) > 1 and h[-2]["addrs"] is not None
               and self.session is not None and self.session.active)
        self.undo_btn.configure(state="normal" if can else "disabled")

    def on_undo(self) -> None:
        if len(self.history) > 1:
            self._revert(len(self.history) - 2)

    def on_history_pick(self) -> None:
        labels = [self._hist_label(e) for e in self.history]
        try:
            k = labels.index(self.hist_var.get())
        except ValueError:
            return
        if k == len(self.history) - 1:
            return
        self._revert(k)

    def _revert(self, k: int) -> None:
        if self.scanning or not self.session or not self.session.active:
            return
        e = self.history[k]
        if e["addrs"] is None:
            messagebox.showinfo("Scanner", f"Scan {e['no']} cannot be restored ({e['why']}).")
            self._sync_history()
            return
        spec, pid, align = self.scan_spec, self.scan_pid, max(1, self.scan_align)
        flags = self._flags(True) & ~TS_FLOAT_SIMPLE        # keep every saved address

        def work() -> None:
            addrs = sorted(set(struct.unpack(f"<{len(e['addrs']) // 8}Q", e["addrs"])))
            vl = self.session.value_len
            segs: list[list[int]] = []
            for a in addrs:                 # runs spaced by the scan alignment become one segment
                if segs and a - segs[-1][2] == align and segs[-1][1] + align <= 0xFFFF0000:
                    segs[-1][1] += align
                    segs[-1][2] = a
                else:
                    segs.append([a, vl, a])
            if len(segs) > (1 << 20):
                raise ProtocolError("too many separate addresses to restore this scan")
            if not segs:
                raise ProtocolError("that scan had no results")
            if self.session.active:
                self.session.end()
            n = self.session.first_scan(pid, [(a, ln) for a, ln, _l in segs], spec.tid, 11, b"", None, align, flags,
                                        on_progress=self._progress, keep_first=True, include_zeros=True)
            self.scan_no = e["no"]
            del self.history[k + 1:]
            e["count"] = n
            gone = len(addrs) - n
            self._after_scan(n, f"Back to scan {e['no']}: {n:,} result(s)"
                             + (f" ({gone:,} no longer readable)" if gone > 0 else "")
                             + ".  Values re-read now; 'Previous' = the value at the undo.")

        self._run(work, f"Going back to scan {e['no']}…")

    def on_cancel(self) -> None:
        pid = self.scan_pid

        def work() -> None:
            with self.aux_lock:
                c = self._aux()
                if c is None:
                    return
                try:
                    c.turbo_cancel(pid)
                    self._post(lambda: self.status_var.set("Cancelling… (results so far are partial)"))
                except Exception as exc:
                    self._post(lambda e=exc: self.status_var.set(f"cancel failed: {e}"))
        threading.Thread(target=work, daemon=True).start()

    # -------------------------------------------------------------- results
    def _goto_page(self, page: int) -> None:
        if self.scanning or not self.session or not self.session.active:
            return
        total = self.session.count
        last = max(0, (total - 1) // PAGE)
        page = max(0, min(page, last))
        if page == self.page and self.rows:
            return

        def work() -> None:
            rows = self.session.get(page * PAGE, PAGE)
            self.page = page
            self._post(lambda: self._show_page(rows))
        self._run(work, "Loading results…")

    def _show_page(self, rows: list) -> None:
        self.rows = rows
        self.res.delete(*self.res.get_children())
        spec = self.scan_spec
        total = self.session.count if (self.session and self.session.active) else 0
        self.found_var.set(f"Found: {total:,}")
        if total > PAGE:
            a = self.page * PAGE
            self.page_var.set(f"{a + 1:,}–{min(total, a + PAGE):,}")
        else:
            self.page_var.set("")
        if not rows or spec is None:
            return
        three = rows[0].first is not None
        for i, r in enumerate(rows):
            vals = (f"{r.addr:X}", spec.decode(r.current), spec.decode(r.previous),
                    spec.decode(r.first) if three else "")
            self.res.insert("", "end", iid=str(i), values=vals, tags=("odd",) if i % 2 else ())

    def _sel_results(self) -> list:
        out = []
        for iid in self.res.selection():
            i = int(iid)
            if i < len(self.rows):
                out.append(self.rows[i])
        return out

    def add_selected_results(self) -> None:
        spec = self.scan_spec
        if spec is None:
            return
        for r in self._sel_results():
            self._add_entry(Entry("No description", r.addr, TypeSpec(**spec.__dict__)))

    def _copy_res_addr(self) -> None:
        sel = self._sel_results()
        if sel:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(f"0x{r.addr:X}" for r in sel))

    def _res_menu(self, event) -> None:
        iid = self.res.identify_row(event.y)
        if iid and iid not in self.res.selection():
            self.res.selection_set(iid)
        sel = self._sel_results()
        if not sel:
            return
        a = sel[0].addr
        m = tk.Menu(self.root, tearoff=0)
        m.add_command(label=f"Add {len(sel)} to address list", command=self.add_selected_results)
        m.add_command(label="Copy address", command=self._copy_res_addr)
        m.add_separator()
        m.add_command(label="Browse this memory (hex)", command=lambda: self.app._hex_goto_value(a & ~0xF))
        m.add_command(label="Find out what writes to this address",
                      command=lambda: self._watch(a, "write"))
        m.add_command(label="Find out what accesses this address",
                      command=lambda: self._watch(a, "read/write"))
        m.add_command(label="Breakpoint (choose type)...", command=lambda: self._bp_dialog(a))
        m.add_separator()
        m.add_command(label="Pointer scan for this address…", command=lambda: self.open_pointer_scan(a))
        m.tk_popup(event.x_root, event.y_root)

    def open_pointer_scan(self, addr: Optional[int] = None) -> None:
        from pointer_scan_dialog import PointerScanWindow   # noqa: PLC0415
        if addr is None:
            sel = self._sel_entries()
            addr = sel[0].addr if sel else None
        PointerScanWindow.open(self.app, self, addr)

    def add_pointer_entries(self, chains: list, type_label: str = "4 Bytes") -> None:
        spec = self._spec_for_label(type_label)
        for c in chains:
            self.entries.append(Entry(f"P→ {c.module}+{c.base_off:X} " + " ".join(f"{o:X}" for o in c.offsets),
                                      0, spec, chain=c))
        self._refresh_list()
        self.app.log_line(f"scanner: added {len(chains)} pointer(s) to the address list")

    def _spec_for_label(self, label: str) -> "TypeSpec":
        u, _sgn, size = VALUE_TYPES.get(label, VALUE_TYPES["4 Bytes"])
        signed = {"4 Bytes": 5, "2 Bytes": 3, "8 Bytes": 7}.get(label)
        return TypeSpec(label, signed if signed is not None else u, size)

    def _bp_dialog(self, addr: int) -> None:
        dbg = getattr(self.app, "debugger", None)
        if dbg is not None:
            dbg.open_bp_dialog(addr, "write")

    def _watch(self, addr: int, kind: str) -> None:
        size = (self.scan_spec.size if self.scan_spec else 4) or 4
        size = size if size in (1, 2, 4, 8) else 4
        dbg = getattr(self.app, "debugger", None)
        if dbg is None:
            return
        dbg.add_watchpoint(addr, size, kind)
        self.app.notebook.select(self.app._debug_tab)

    # ------------------------------------------------------------ live loop
    def _live_loop(self) -> None:
        """Every ~0.6 s: read the visible result rows + the address list in ONE bulk read."""
        while not self._stop.is_set():
            time.sleep(0.6)
            try:
                if not self._visible():
                    continue
                spec = self.scan_spec
                pid = self.scan_pid or self._pid_quiet()
                if not pid:
                    continue
                want: list[tuple[int, int]] = []
                res_rows = list(self.rows[:PAGE]) if spec else []
                if spec and spec.size:
                    want += [(r.addr, spec.size) for r in res_rows]
                ents = list(self.entries)
                epid = self._pid_quiet() or pid
                with self.aux_lock:
                    c = self._aux()
                    if c is None:
                        continue
                    ptrs = [e for e in ents if e.chain is not None]
                    if ptrs:                    # pointer entries: follow the chain again (game may have moved it)
                        self._resolve_ptr_entries(c, epid, ptrs)
                    ents = [e for e in ents if e.addr]
                    want += [(e.addr, e.spec.size or 1) for e in ents]
                    if not want:
                        if ptrs:
                            self._post(self._refresh_ptr_cells)
                        continue
                    data = c.read_multi(pid if not ents else epid, want)
                k = len(res_rows) if (spec and spec.size) else 0
                res_data, ent_data = data[:k], data[k:]
                self._post(lambda rr=res_rows, rd=res_data, ee=ents, ed=ent_data: self._apply_live(rr, rd, ee, ed))
            except Exception:
                continue

    def _resolve_ptr_entries(self, c, pid: int, ptrs: list) -> None:
        import pointer_scan as ps   # noqa: PLC0415
        now = time.monotonic()
        if getattr(self, "_ptr_maps", None) is None or now - getattr(self, "_ptr_maps_t", 0) > 5:
            self._ptr_maps, self._ptr_maps_t = c.maps(pid), now
        try:
            addrs = ps.resolve(c, pid, [e.chain for e in ptrs], self._ptr_maps)
        except Exception:
            self._ptr_maps = None
            raise
        for e, a in zip(ptrs, addrs):
            e.addr = a or 0
            if not a:
                e.value = "??"

    def _refresh_ptr_cells(self) -> None:
        for e in self.entries:
            if e.chain is not None and e.iid and self.lst.exists(e.iid):
                self.lst.set(e.iid, "addr", self._addr_text(e))
                self.lst.set(e.iid, "value", e.value)

    def _pid_quiet(self) -> int:
        try:
            return self.app._pid()
        except Exception:
            return 0

    def _visible(self) -> bool:
        try:
            return self.app.notebook.select() == str(self.app._scanner_tab) and self.app.client.connected
        except Exception:
            return False

    def _apply_live(self, rows, rdata, ents, edata) -> None:
        spec = self.scan_spec
        if rows is self.rows or rows == self.rows[: len(rows)]:
            for i, (r, d) in enumerate(zip(rows, rdata)):
                iid = str(i)
                if not self.res.exists(iid):
                    break
                txt = spec.decode(d)
                if self.res.set(iid, "value") != txt:
                    self.res.set(iid, "value", txt)
                tags = ["odd"] if i % 2 else []
                if d != r.current:
                    tags.append("chg")
                self.res.item(iid, tags=tags)
        for e, d in zip(ents, edata):
            e.value = e.spec.decode(d)
            if e.iid and self.lst.exists(e.iid) and self.lst.set(e.iid, "value") != e.value:
                self.lst.set(e.iid, "value", e.value)
        self._refresh_ptr_cells()

    # ----------------------------------------------------------- freeze loop
    def _freeze_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(0.1)
            frozen = [e for e in self.entries if e.frozen and e.freeze_data and e.addr]
            if not frozen:
                continue
            pid = self._pid_quiet()
            if not pid or not self.app.client.connected:
                continue
            try:
                with self.aux_lock:
                    c = self._aux()
                    if c is not None:
                        c.write_multi(pid, [(e.addr, e.freeze_data) for e in frozen])
            except Exception:
                continue

    # ----------------------------------------------------------- address list
    def _add_entry(self, e: Entry) -> None:
        self.entries.append(e)
        self._refresh_list()

    def _refresh_list(self) -> None:
        self.lst.delete(*self.lst.get_children())
        for i, e in enumerate(self.entries):
            e.iid = str(i)
            tags = ["odd"] if i % 2 else []
            if e.frozen:
                tags.append("frozen")
            self.lst.insert("", "end", iid=e.iid, tags=tags, values=(
                "☑" if e.frozen else "☐", e.desc, self._addr_text(e), self._type_text(e.spec), e.value))

    @staticmethod
    def _addr_text(e: "Entry") -> str:
        if e.chain is None:
            return f"{e.addr:X}"
        return f"P→ {e.addr:X}" if e.addr else "P→ ??"

    @staticmethod
    def _type_text(spec: TypeSpec) -> str:
        t = spec.label
        if spec.label in ("String", "Array of bytes"):
            t += f"[{spec.size}]"
        elif spec.tid in (1, 3, 5, 7):
            t += " (signed)"
        if spec.hex:
            t += " hex"
        return t

    def _sel_entries(self) -> list[Entry]:
        return [self.entries[int(i)] for i in self.lst.selection() if int(i) < len(self.entries)]

    def _lst_click(self, event) -> None:
        if self.lst.identify_column(event.x) == "#1" and self.lst.identify_row(event.y):
            iid = self.lst.identify_row(event.y)
            self.lst.selection_set(iid)
            self.toggle_freeze()
            return "break"

    def toggle_freeze(self) -> None:
        sel = self._sel_entries()
        if not sel:
            return
        want = not sel[0].frozen
        need_read = [e for e in sel if want]

        def work() -> None:
            pid = self._pid_quiet()
            datas = []
            if need_read and pid:
                with self.aux_lock:
                    c = self._aux()
                    if c is not None:
                        datas = c.read_multi(pid, [(e.addr, e.spec.size or 1) for e in need_read])
            def ui() -> None:
                for e in sel:
                    e.frozen = want
                for e, d in zip(need_read, datas):
                    e.freeze_data = d
                self._refresh_list()
            self._post(ui)
        threading.Thread(target=work, daemon=True).start()

    def _lst_double(self, event) -> None:
        iid = self.lst.identify_row(event.y)
        col = self.lst.identify_column(event.x)
        if not iid:
            return
        e = self.entries[int(iid)]
        if col == "#2":
            t = simpledialog.askstring("Description", "Description:", initialvalue=e.desc, parent=self.root)
            if t is not None:
                e.desc = t
                self._refresh_list()
        elif col == "#3":
            t = simpledialog.askstring("Address", "Address (hex):", initialvalue=f"{e.addr:X}", parent=self.root)
            if t:
                try:
                    e.addr = self.app.eval_full(t if t.lower().startswith(("0x", "@", "[", "module", "$")) else "0x" + t)
                    e.chain = None              # a typed address replaces the pointer chain
                    self._refresh_list()
                except Exception as exc:
                    self.app._fail(exc)
        else:
            self._edit_value([e])

    def _edit_value(self, ents: list[Entry]) -> None:
        if not ents:
            return
        e = ents[0]
        t = simpledialog.askstring("Change value", f"New value for {len(ents)} address(es) ({self._type_text(e.spec)}):",
                                   initialvalue=e.value if e.value != "?" else "", parent=self.root)
        if t is None:
            return
        try:
            data, _m = e.spec.encode(t)
            if e.spec.label in ("String", "Array of bytes") and e.spec.size and len(data) > e.spec.size:
                raise ValueError(f"value is {len(data)} bytes, the entry is {e.spec.size}")
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return

        def work() -> None:
            with self.aux_lock:
                c = self._aux()
                if c is None:
                    return
                c.write_multi(pid, [(x.addr, data) for x in ents])
            def ui() -> None:
                for x in ents:
                    if x.frozen:
                        x.freeze_data = data
                self.app.log_line(f"scanner: wrote {t} to {len(ents)} address(es)")
            self._post(ui)
        threading.Thread(target=work, daemon=True).start()

    def _lst_menu(self, event) -> None:
        iid = self.lst.identify_row(event.y)
        if iid and iid not in self.lst.selection():
            self.lst.selection_set(iid)
        sel = self._sel_entries()
        if not sel:
            return
        a = sel[0].addr
        m = tk.Menu(self.root, tearoff=0)
        m.add_command(label="Change value…", command=lambda: self._edit_value(sel))
        m.add_command(label="Freeze / unfreeze  (Space)", command=self.toggle_freeze)
        m.add_command(label="Change type…", command=lambda: self._change_type(sel))
        m.add_separator()
        m.add_command(label="Browse this memory (hex)", command=lambda: self.app._hex_goto_value(a & ~0xF))
        m.add_command(label="Find out what writes to this address", command=lambda: self._watch(a, "write"))
        m.add_command(label="Find out what accesses this address", command=lambda: self._watch(a, "read/write"))
        m.add_command(label="Breakpoint (choose type)...", command=lambda: self._bp_dialog(a))
        m.add_command(label="Copy address", command=lambda: (self.root.clipboard_clear(),
                                                             self.root.clipboard_append(f"0x{a:X}")))
        if sel[0].chain is not None:
            ex = sel[0].chain.expr()
            m.add_command(label="Copy pointer expression", command=lambda: (
                self.root.clipboard_clear(), self.root.clipboard_append(ex)))
        m.add_command(label="Pointer scan for this address…", command=lambda: self.open_pointer_scan(a))
        m.add_separator()
        m.add_command(label="Delete", command=self.on_delete_entries)
        m.tk_popup(event.x_root, event.y_root)

    def _change_type(self, sel: list[Entry]) -> None:
        win = tk.Toplevel(self.root)
        win.title("Change type")
        win.transient(self.root)
        f = ttk.Frame(win, padding=12)
        f.pack(fill="both", expand=True)
        tv = tk.StringVar(value=sel[0].spec.label)
        sv = tk.BooleanVar(value=sel[0].spec.tid in (1, 3, 5, 7))
        hv = tk.BooleanVar(value=sel[0].spec.hex)
        ln = tk.StringVar(value=str(sel[0].spec.size or 4))
        ttk.Combobox(f, textvariable=tv, values=list(VALUE_TYPES), state="readonly").grid(row=0, column=0, columnspan=2)
        ttk.Checkbutton(f, text="Signed", variable=sv).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(f, text="Hex", variable=hv).grid(row=1, column=1, sticky="w")
        ttk.Label(f, text="Length (string / bytes)").grid(row=2, column=0, sticky="w")
        ttk.Entry(f, textvariable=ln, width=6).grid(row=2, column=1, sticky="w")

        def ok() -> None:
            u, s, size = VALUE_TYPES[tv.get()]
            try:
                size = size or int(ln.get(), 0)
            except ValueError:
                return
            for e in sel:
                e.spec = TypeSpec(tv.get(), s if sv.get() else u, size, hv.get() and u <= 7, e.spec.utf16)
                e.frozen = False
            win.destroy()
            self._refresh_list()
        ttk.Button(f, text="OK", style="Accent.TButton", command=ok).grid(row=3, column=0, columnspan=2, pady=(10, 0))

    def on_add_manual(self) -> None:
        t = simpledialog.askstring("Add address", "Address (0x…, module(eboot.bin)+0x10, [ptr]+8 …):",
                                   parent=self.root)
        if not t:
            return
        try:
            addr = self.app.eval_full(t)
        except Exception as exc:
            self.app._fail(exc)
            return
        spec = self._spec()
        if spec.size == 0:
            spec.size = 16
        self._add_entry(Entry("No description", addr, spec))

    def on_delete_entries(self) -> None:
        sel = set(id(e) for e in self._sel_entries())
        if sel:
            self.entries = [e for e in self.entries if id(e) not in sel]
            self._refresh_list()

    def _tables_dir(self) -> Path:
        d = APP_DIR / "tables"
        d.mkdir(exist_ok=True)
        return d

    def on_save_table(self) -> None:
        path = filedialog.asksaveasfilename(initialdir=str(self._tables_dir()), defaultextension=".json",
                                            filetypes=[("Address table", "*.json")], parent=self.root)
        if not path:
            return
        data = {"format": "ps5table/1", "entries": [
            {"desc": e.desc, "addr": f"0x{e.addr:X}", "type": e.spec.to_dict(),
             **({"ptr": e.chain.to_list()} if e.chain is not None else {})} for e in self.entries]}
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.app.log_line(f"scanner: saved {len(self.entries)} address(es) to {path}")

    def on_load_table(self) -> None:
        path = filedialog.askopenfilename(initialdir=str(self._tables_dir()),
                                          filetypes=[("Address table", "*.json"), ("All", "*.*")], parent=self.root)
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            for d in data.get("entries", []):
                chain = None
                if d.get("ptr"):
                    import pointer_scan as ps   # noqa: PLC0415
                    chain = ps.Chain.from_list(d["ptr"])
                self.entries.append(Entry(d.get("desc", ""), int(str(d["addr"]), 0), TypeSpec.from_dict(d["type"]),
                                          chain=chain))
        except Exception as exc:
            self.app._fail(exc)
            return
        self._refresh_list()

    def on_copy_cheat(self) -> None:
        """Selected (or all) entries as a toggle cheat for the Cheat Editor."""
        ents = self._sel_entries() or self.entries
        if not ents:
            return
        tmap = {0: "u8", 1: "i8", 2: "u16", 3: "i16", 4: "u32", 5: "i32", 6: "u64", 7: "i64", 8: "f32", 9: "f64"}
        steps = []
        for e in ents:
            if e.spec.tid in tmap:
                val = e.value if e.value not in ("?", "??") else "0"
                if e.spec.hex and e.spec.is_int:
                    val = "0x" + val
                steps.append({"op": "patch", "addr": e.chain.expr() if e.chain is not None else f"0x{e.addr:X}",
                              "type": tmap[e.spec.tid],
                              "value": float(val) if e.spec.is_float else val})
            else:
                data = (e.freeze_data or b"").hex(" ")
                steps.append({"op": "patch", "addr": e.chain.expr() if e.chain is not None else f"0x{e.addr:X}",
                              "type": "hex", "value": data})
        cheat = {"name": ents[0].desc if len(ents) == 1 else "Scanner values", "mode": "toggle", "steps": steps}
        self.root.clipboard_clear()
        self.root.clipboard_append(json.dumps(cheat, indent=2))
        self.app.log_line(f"scanner: copied a cheat with {len(steps)} patch step(s) to the clipboard")
