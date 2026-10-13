"""Build a cheat automatically from the current Caller / Hex tab state."""

from __future__ import annotations

import json
import re
import struct
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import messagebox, ttk
from typing import Any, Optional

from cheats import Cheat, Game, ensure_string_params
from scrollable import ScrollFrame, fit_geometry
import theme  # noqa: E402

MAX_BUF_SNAPSHOT = 0x10000
M64 = (1 << 64) - 1
KIND_TYPE = {
    "u64 / pointer": "u64", "i64": "i64", "u32": "u32", "i32": "i32",
    "float bits": "f32", "double bits": "f64",
}
TYPE_WIDTH = {"u32": 4, "i32": 4, "u64": 8, "i64": 8, "f32": 4, "f64": 8}


@dataclass
class ArgSnap:
    reg: str
    kind: str
    text: str
    value: int                  # resolved register bits
    editable: bool = False
    item_list: str = ""         # item list the value was picked from ("" = none)


@dataclass
class BufSnap:
    name: str
    addr: int
    size: int
    data: Optional[bytes] = None
    prot: str = ""
    referenced: bool = False


@dataclass
class ParamSpec:
    index: int                  # which register
    name: str
    type: str
    default: str
    items: str = ""

    def to_dict(self) -> dict:
        d = {"name": self.name, "label": self.name.replace("_", " ").title(),
             "type": self.type, "default": self.default}
        if self.items:
            d["items"] = self.items
        return d


@dataclass
class CodeVar:
    """A $name used by quick-code assembly. as_input -> becomes a cheat param,
    otherwise it is fixed with a `set` step to `expr`."""
    name: str
    type: str = "u64"
    default: str = "0"
    items: str = ""
    as_input: bool = True
    expr: str = "0"


_DOLLAR = re.compile(r"\$([A-Za-z_]\w*)")
_PLAIN_NUM = re.compile(r"-?(0[xX][0-9a-fA-F]+|\d+)")


def code_var_rows(snap: "Snapshot") -> list[dict]:
    """Every $variable the recorded quick-code buffers define or use."""
    rows: dict[str, dict] = {}
    for bname, src in snap.code.items():
        for vname, (expr, val) in src.get("vars", {}).items():
            r = rows.setdefault(vname, {"name": vname, "expr": expr, "value": val, "owners": set()})
            r["owners"].add(bname)
        asm = "\n".join(line.split(";", 1)[0] for line in src.get("asm", "").split("\n"))
        for used in _DOLLAR.findall(asm):
            if used == "ret":
                continue
            r = rows.setdefault(used, {"name": used, "expr": "0", "value": 0, "owners": set()})
            r["owners"].add(bname)
    return list(rows.values())


def _fmt_default(v: int) -> str:
    v &= M64
    return str(v) if v < 10 else f"0x{v:X}"


@dataclass
class Snapshot:
    pid: int
    title_id: str
    proc_name: str
    maps: list
    buffers: list[BufSnap]
    rip: int
    args: list[ArgSnap]
    patches: list[tuple[int, bytes, bytes]] = field(default_factory=list)  # addr, new, orig
    warnings: list[str] = field(default_factory=list)
    code: dict = field(default_factory=dict)   # quick-code buffer name -> {asm, vars, prot, auto_ret}
    view: Optional[tuple] = None               # (base, current bytes, original bytes) of the hex view


# ---------------------------------------------------------------- gathering
def prot_letters(p: int) -> str:
    return ("r" if p & 1 else "") + ("w" if p & 2 else "") + ("x" if p & 4 else "")


def collect(app, pid: int, rip: int, args: list[ArgSnap], patches) -> Snapshot:
    """Runs in a background thread (talks to the console)."""
    client = app.client
    info = client.proc_info(pid)
    maps = client.maps(pid)
    snap = Snapshot(pid, info.titleid.strip().upper(), info.name, maps, [], rip, args, patches)
    live = {b.name for b in app.state.buffers}
    snap.code = {n: dict(v) for n, v in getattr(app, "code_sources", {}).items() if n in live}
    values = [rip] + [a.value for a in args]
    for b in list(app.state.buffers):
        bs = BufSnap(b.name, b.address, b.size)
        for m in maps:
            if m.start <= b.address < m.end:
                bs.prot = prot_letters(m.prot)
                break
        if b.size <= MAX_BUF_SNAPSHOT:
            try:
                bs.data = client.read(pid, b.address, b.size)
            except Exception as exc:
                snap.warnings.append(f"could not read @{b.name}: {exc}")
        else:
            snap.warnings.append(f"@{b.name} is larger than 0x{MAX_BUF_SNAPSHOT:X}; contents not captured")
        bs.referenced = any(b.address <= v < b.address + b.size for v in values if v)
        snap.buffers.append(bs)
    used = with_code_deps(snap, {b.name for b in snap.buffers if b.referenced})
    for bs in snap.buffers:
        bs.referenced = bs.referenced or bs.name in used
    return snap


# ------------------------------------------------------------------ building
_REF = re.compile(r"@([A-Za-z_][\w.]*)")


def code_refs(src: dict) -> set[str]:
    names: set[str] = set()
    for line in src.get("asm", "").split("\n"):
        names.update(_REF.findall(line.split(";", 1)[0]))
    for expr, _v in src.get("vars", {}).values():
        names.update(_REF.findall(str(expr)))
    return names


def with_code_deps(snap: "Snapshot", sel: set[str]) -> set[str]:
    """Selected buffers + every buffer their quick-code uses (@stats inside the asm...),
    so a recorded cheat always allocates what its code reads."""
    out, todo = set(sel), list(sel)
    known = {b.name for b in snap.buffers}
    while todo:
        n = todo.pop()
        for m in code_refs(snap.code.get(n, {})):
            if m in known and m not in out:
                out.add(m)
                todo.append(m)
    return out


def _symbolize(snap: Snapshot, sel: set[str], aslr: bool, addr: int) -> Optional[str]:
    for b in snap.buffers:
        if b.name in sel and b.addr <= addr < b.addr + max(b.size, 1):
            off = addr - b.addr
            return f"@{b.name}" + (f"+0x{off:X}" if off else "")
    if aslr and addr >= 0x10000:
        for m in snap.maps:
            if m.name and m.start <= addr < m.end:
                base = min(x.start for x in snap.maps if x.name == m.name)
                off = addr - base
                return f"module({m.name})" + (f"+0x{off:X}" if off else "")
    return None


def _num(addr: int) -> Any:
    return addr if addr < 0x10000 else f"0x{addr:X}"


_PH = re.compile(r"\{[A-Za-z_]\w*\}")


def _placeholder_text(data: bytes) -> Optional[tuple[str, str]]:
    """If `data` is a NUL-terminated utf8/utf16 string containing {name}, return (type, text)."""
    try:
        s8 = data.split(b"\0", 1)[0].decode("utf-8")
        if _PH.search(s8) and not any(data[len(s8.encode("utf-8")):]):
            return "utf8", s8
    except UnicodeDecodeError:
        pass
    try:
        end = next((i for i in range(0, len(data) - 1, 2) if data[i:i + 2] == b"\0\0"), len(data) & ~1)
        s16 = data[:end].decode("utf-16le")
        if _PH.search(s16) and not any(data[end:]):
            return "utf16", s16
    except UnicodeDecodeError:
        pass
    return None


def merge_patch_runs(snap: Snapshot, gap: int) -> list[tuple[int, bytes, bytes]]:
    """Join hex-edit runs that are at most `gap` bytes apart into single blocks
    (addr, new bytes, original bytes). The bytes between two edits are taken from
    the hex view, so they are written back with the value they had when you
    opened the view."""
    runs = sorted(snap.patches, key=lambda r: r[0])
    if len(runs) < 2 or snap.view is None:
        return runs
    base, cur, orig = snap.view

    def block(start: int, end: int) -> tuple[int, bytes, bytes]:
        off = start - base
        return start, bytes(cur[off:off + end - start]), bytes(orig[off:off + end - start])

    out: list[tuple[int, bytes, bytes]] = []
    start, end = runs[0][0], runs[0][0] + len(runs[0][1])
    for addr, new, _o in runs[1:]:
        if addr - end <= gap and 0 <= start - base and addr + len(new) - base <= len(cur):
            end = max(end, addr + len(new))
        else:
            out.append(block(start, end) if 0 <= start - base and end - base <= len(cur) else
                       next(r for r in runs if r[0] == start))
            start, end = addr, addr + len(new)
    out.append(block(start, end) if 0 <= start - base and end - base <= len(cur) else
               next(r for r in runs if r[0] == start))
    return out


def build_steps(snap: Snapshot, sel: set[str], aslr: bool, include_call: bool,
                include_patches: bool, check_orig: bool, free_after: bool,
                params: dict[int, ParamSpec], bindings: list[tuple[str, int, int]],
                code_vars: Optional[list[CodeVar]] = None,
                merge_gap: Optional[int] = None) -> list[dict]:
    steps: list[dict] = []
    sel = with_code_deps(snap, sel)
    sym = lambda a: _symbolize(snap, sel, aslr, a) or _num(a)

    for b in snap.buffers:
        if b.name not in sel or b.name in snap.code:
            continue
        st: dict[str, Any] = {"op": "alloc", "name": b.name, "size": b.size}
        if b.prot:
            st["prot"] = b.prot
        if b.data and any(b.data):
            text = _placeholder_text(b.data)
            if text is not None:
                # buffer holds text like "{playername}" -> keep it as text so the
                # cheat asks for the value each run
                st["init"] = {"type": text[0], "value": text[1]}
            else:
                st["init"] = {"type": "hex", "value": b.data.hex(), "nul": False}
        steps.append(st)

    # quick-code: fixed variables, then the assembly itself (re-assembled each run
    # so $inputs, @buffers and module() are always current)
    for cv in code_vars or []:
        if not cv.as_input:
            steps.append({"op": "set", "var": cv.name, "value": cv.expr})
    for b in snap.buffers:
        if b.name in sel and b.name in snap.code:
            src = snap.code[b.name]
            st = {"op": "code", "name": b.name, "asm": src["asm"].rstrip("\n")}
            if src.get("prot") not in (None, "rx"):
                st["prot"] = src["prot"]
            if src.get("auto_ret") is False:
                st["auto_ret"] = False
            if src.get("auto_frame") is False:
                st["auto_frame"] = False
            steps.append(st)

    # editable values written into buffers (e.g. an item id inside a struct)
    for bname, off, idx in bindings:
        p = params.get(idx)
        if p and bname in sel:
            steps.append({"op": "write", "addr": f"@{bname}" + (f"+0x{off:X}" if off else ""),
                          "type": p.type, "value": f"${p.name}"})

    if include_patches:
        runs = merge_patch_runs(snap, merge_gap) if merge_gap is not None else snap.patches
        for addr, new, orig in runs:
            if check_orig:
                steps.append({"op": "check", "addr": sym(addr), "type": "hex", "value": orig.hex(" "),
                              "msg": f"bytes at 0x{addr:X} differ - wrong game version?"})
            steps.append({"op": "patch", "addr": sym(addr), "type": "hex", "value": new.hex(" ")})

    if include_call and snap.rip:
        call_args: list[Any] = []
        for i, a in enumerate(snap.args):
            p = params.get(i)
            if p:
                ref = f"${p.name}"
                call_args.append(ref if p.type in ("u64", "ptr") else {"type": p.type, "value": ref})
            elif a.kind == "float bits":
                call_args.append({"type": "f32", "value": float(a.text.strip() or "0")})
            elif a.kind == "double bits":
                call_args.append({"type": "f64", "value": float(a.text.strip() or "0")})
            elif a.kind == "i32":
                v = a.value & 0xFFFFFFFF
                call_args.append({"type": "i32", "value": v - (1 << 32) if v >> 31 else v})
            elif a.kind == "u32":
                call_args.append({"type": "u32", "value": a.value & 0xFFFFFFFF})
            elif a.kind == "i64":
                call_args.append({"type": "i64", "value": struct.unpack("<q", struct.pack("<Q", a.value))[0]})
            else:
                call_args.append(sym(a.value))
        while call_args and call_args[-1] == 0:
            call_args.pop()
        steps.append({"op": "call", "rip": sym(snap.rip), "args": call_args, "store": "ret"})

    if free_after:
        for b in snap.buffers:
            if b.name in sel:
                steps.append({"op": "free", "name": b.name})
    return steps


# -------------------------------------------------------------------- dialog
class RecordDialog:
    NEW = "<new game file>"
    NONE = "(none)"

    def __init__(self, tab, snap: Snapshot) -> None:
        self.tab, self.snap = tab, snap
        self.app = tab.app
        self.items = self.app.items
        self._ready = False
        self.bindings: list[tuple[str, int, int]] = []
        app = self.app

        self.win = tk.Toplevel(app.root)
        self.win.title("Record cheat from Caller")
        fit_geometry(self.win, 1320, 780)
        self.win.transient(app.root)

        v = tk.StringVar
        self.game_choice = v()
        self.game_name = v(value=snap.proc_name or snap.title_id or "New game")
        self.title_id = v(value=snap.title_id)
        self.cheat_name = v(value="New cheat")
        self.desc = v()
        self.mode = v(value="once")
        self.aslr = tk.BooleanVar(value=True)
        self.inc_call = tk.BooleanVar(value=bool(snap.rip))
        self.inc_patch = tk.BooleanVar(value=bool(snap.patches))
        self.chk_orig = tk.BooleanVar(value=False)   # optional: verify original bytes first
        self.merge = tk.BooleanVar(value=len(snap.patches) > 1 and snap.view is not None)
        self.merge_gap = tk.StringVar(value="64")
        self.free_after = tk.BooleanVar(value=False)
        if snap.patches and not snap.rip:
            self.mode.set("toggle")

        bottom = ttk.Frame(self.win, padding=(8, 4, 8, 8))
        bottom.pack(side="bottom", fill="x")             # first: always visible, whatever the screen size
        ttk.Button(bottom, text="Save cheat", style="Accent.TButton", command=self.on_save).pack(side="left")
        ttk.Button(bottom, text="Cancel", command=self.win.destroy).pack(side="left", padx=6)
        ttk.Separator(self.win).pack(side="bottom", fill="x")
        lscroll = ScrollFrame(self.win, horizontal=False)  # the options column scrolls on short screens
        lscroll.pack(side="left", fill="y")
        lscroll.canvas.configure(width=330)
        left = ttk.Frame(lscroll.body, padding=8)
        left.pack(fill="both", expand=True)
        mid = ttk.Frame(self.win, padding=8)
        mid.pack(side="left", fill="y")
        right = ttk.Frame(self.win, padding=8)
        right.pack(side="left", fill="both", expand=True)

        # ---- left: metadata + options
        names = [f"{g.name} [{g.title_id}]" for g in tab.games]
        match = next((n for n, g in zip(names, tab.games) if snap.title_id and g.title_id == snap.title_id), self.NEW)
        self.game_choice.set(match)
        ttk.Label(left, text="Save into").pack(anchor="w")
        ttk.Combobox(left, textvariable=self.game_choice, values=names + [self.NEW],
                     state="readonly", width=36).pack(anchor="w", pady=(0, 6))
        for label, var in (("Game name (new file)", self.game_name), ("Title ID (new file)", self.title_id),
                           ("Cheat name", self.cheat_name), ("Description", self.desc)):
            ttk.Label(left, text=label).pack(anchor="w")
            ttk.Entry(left, textvariable=var, width=38).pack(anchor="w", pady=(0, 6))
        ttk.Label(left, text="Mode").pack(anchor="w")
        ttk.Combobox(left, textvariable=self.mode, values=("once", "toggle"), state="readonly",
                     width=12).pack(anchor="w", pady=(0, 8))

        ttk.Label(left, text="Buffers to include (allocated + contents)").pack(anchor="w")
        self.lb = tk.Listbox(left, selectmode="multiple", height=6, exportselection=False, width=38)
        for i, b in enumerate(snap.buffers):
            self.lb.insert("end", f"@{b.name}  0x{b.addr:X}  {b.size}b" + ("   (used)" if b.referenced else ""))
            if b.referenced:
                self.lb.selection_set(i)
        self.lb.pack(anchor="w", pady=(0, 8))
        self.lb.bind("<<ListboxSelect>>", lambda _e: self.refresh())

        def check(text: str, var: tk.BooleanVar) -> None:
            ttk.Checkbutton(left, text=text, variable=var, command=self.refresh).pack(anchor="w")

        check("Include the function call", self.inc_call)
        check("Make addresses ASLR-safe (module(...)+off)", self.aslr)
        check(f"Include pending hex edits ({len(snap.patches)} run(s))", self.inc_patch)
        mrow = ttk.Frame(left)
        mrow.pack(anchor="w")
        ttk.Checkbutton(mrow, text="  ...merge nearby edits into ONE write (gap up to", variable=self.merge,
                        command=self.refresh).pack(side="left")
        ttk.Entry(mrow, textvariable=self.merge_gap, width=5).pack(side="left", padx=2)
        ttk.Label(mrow, text="bytes)").pack(side="left")
        self.merge_gap.trace_add("write", lambda *_: self.refresh())
        ttk.Label(left, foreground=theme.c("muted"), wraplength=300,
                  text="     Bytes between two edits are written back with the value they had when you opened "
                       "the hex view.").pack(anchor="w")
        check("  ...safety check: stop if the original bytes differ", self.chk_orig)
        check("Free buffers after the call", self.free_after)
        for w in snap.warnings:
            ttk.Label(left, text="! " + w, foreground=theme.c("warn"), wraplength=300).pack(anchor="w")
        self.win.after_idle(lambda: lscroll.canvas.configure(width=left.winfo_reqwidth()))

        # ---- middle: editable values
        ttk.Label(mid, text="Editable values", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(mid, text="Ticked registers become inputs when the cheat runs.\n"
                            "Pick an item list to get a dropdown.", wraplength=380).pack(anchor="w", pady=(0, 4))
        grid = ttk.Frame(mid)
        grid.pack(anchor="w")
        for c, h in enumerate(("edit", "register", "name", "item list")):
            ttk.Label(grid, text=h).grid(row=0, column=c, sticky="w", padx=3)
        self.edit_vars: list[tk.BooleanVar] = []
        self.pname_vars: list[tk.StringVar] = []
        self.plist_vars: list[tk.StringVar] = []
        lists = [self.NONE] + self.items.names()
        used: set[str] = set()
        for i, a in enumerate(snap.args):
            picked = a.item_list if a.item_list in self.items.lists else ""
            base = "item" if picked else "value"
            name = base if base not in used else f"{base}_{a.reg}"
            used.add(name)
            ev, nv, lv = tk.BooleanVar(value=a.editable), tk.StringVar(value=name), tk.StringVar(value=picked or self.NONE)
            self.edit_vars.append(ev)
            self.pname_vars.append(nv)
            self.plist_vars.append(lv)
            ttk.Checkbutton(grid, variable=ev, command=self.on_edit_change).grid(row=i + 1, column=0)
            ttk.Label(grid, text=f"{a.reg} [{a.kind}] = {a.text or '0'}", width=30).grid(row=i + 1, column=1, sticky="w")
            ttk.Entry(grid, textvariable=nv, width=12).grid(row=i + 1, column=2, padx=3)
            ttk.Combobox(grid, textvariable=lv, values=lists, state="readonly", width=14).grid(row=i + 1, column=3)
            nv.trace_add("write", lambda *_: self.on_edit_change())
            lv.trace_add("write", lambda *_: self.refresh())

        # ---- quick-code variables ($name used inside assembly)
        self.cv_rows: list[dict] = []
        cv_info = code_var_rows(snap)
        if cv_info:
            ttk.Separator(mid).pack(fill="x", pady=8)
            ttk.Label(mid, text="Quick-code variables  ($name)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
            ttk.Label(mid, text="Tick 'input' to type a value for it on the Cheats tab each time the cheat "
                                "runs. Unticked ones keep their recorded value.", wraplength=380).pack(anchor="w", pady=(0, 4))
            cg = ttk.Frame(mid)
            cg.pack(anchor="w")
            for c, h in enumerate(("input", "variable", "type", "default", "item list")):
                ttk.Label(cg, text=h).grid(row=0, column=c, sticky="w", padx=3)
            cv_lists = [self.NONE] + self.items.names()
            for i, info in enumerate(cv_info):
                plain = bool(_PLAIN_NUM.fullmatch(info["expr"].strip()))
                row = {
                    "info": info,
                    "in": tk.BooleanVar(value=plain),
                    "type": tk.StringVar(value="u64"),
                    "def": tk.StringVar(value=info["expr"].strip() if plain else _fmt_default(info["value"])),
                    "list": tk.StringVar(value=self.NONE),
                }
                ttk.Checkbutton(cg, variable=row["in"], command=self.on_edit_change).grid(row=i + 1, column=0)
                ttk.Label(cg, text="$" + info["name"], width=12).grid(row=i + 1, column=1, sticky="w")
                ttk.Combobox(cg, textvariable=row["type"], values=("u64", "u32", "i32", "i64"),
                             state="readonly", width=5).grid(row=i + 1, column=2, padx=3)
                ttk.Entry(cg, textvariable=row["def"], width=12).grid(row=i + 1, column=3, padx=3)
                ttk.Combobox(cg, textvariable=row["list"], values=cv_lists, state="readonly",
                             width=12).grid(row=i + 1, column=4)
                for k in ("in", "type", "def", "list"):
                    row[k].trace_add("write", lambda *_: self.on_edit_change())
                self.cv_rows.append(row)

        ttk.Separator(mid).pack(fill="x", pady=8)
        ttk.Label(mid, text="Write editable value into a buffer", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(mid, text="e.g. the item id inside a struct you built in a buffer.",
                  wraplength=380).pack(anchor="w")
        self.bind_lb = tk.Listbox(mid, height=6, width=52, exportselection=False)
        self.bind_lb.pack(anchor="w", pady=4)
        br = ttk.Frame(mid)
        br.pack(anchor="w")
        ttk.Button(br, text="Detect in buffers", command=self.on_detect).pack(side="left", padx=2)
        ttk.Button(br, text="Remove selected", command=self.on_unbind).pack(side="left", padx=2)
        mr = ttk.Frame(mid)
        mr.pack(anchor="w", pady=(6, 0))
        self.m_buf, self.m_off, self.m_par = tk.StringVar(), tk.StringVar(value="0"), tk.StringVar()
        self.m_buf_cb = ttk.Combobox(mr, textvariable=self.m_buf, values=[b.name for b in snap.buffers],
                                     state="readonly", width=9)
        self.m_buf_cb.pack(side="left")
        ttk.Label(mr, text="+").pack(side="left")
        ttk.Entry(mr, textvariable=self.m_off, width=7).pack(side="left")
        ttk.Label(mr, text="<-").pack(side="left", padx=3)
        self.m_par_cb = ttk.Combobox(mr, textvariable=self.m_par, values=[], state="readonly", width=10)
        self.m_par_cb.pack(side="left")
        ttk.Button(mr, text="Add", command=self.on_bind).pack(side="left", padx=4)

        # ---- right: preview
        ttk.Label(right, text=f"Preview  (pid {snap.pid}, title {snap.title_id or '?'})").pack(anchor="w")
        wrap = ttk.Frame(right)
        wrap.pack(fill="both", expand=True)
        self.preview = tk.Text(wrap, wrap="none", font=("Consolas", 10))
        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.preview.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=self.preview.xview)
        self.preview.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.preview.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)

        self._ready = True
        self.on_detect(quiet=True)
        self.refresh()

    # ------------------------------------------------------------ params
    def _default(self, a: ArgSnap, ptype: str, lst: str) -> str:
        if ptype in ("f32", "f64"):
            return a.text.strip() or "0"
        if ptype in ("u32", "i32"):
            v = a.value & 0xFFFFFFFF
            if ptype == "i32" and v >> 31:
                v -= 1 << 32
        elif ptype == "i64":
            v = struct.unpack("<q", struct.pack("<Q", a.value & M64))[0]
        else:
            v = a.value & M64
        if lst:
            nm = self.items.name_of(lst, v) or self.items.name_of(lst, v & M64)
            if nm:
                return nm
        return str(v)

    def _params(self) -> dict[int, ParamSpec]:
        out: dict[int, ParamSpec] = {}
        seen: set[str] = set()
        for i, a in enumerate(self.snap.args):
            if not self.edit_vars[i].get():
                continue
            name = self.pname_vars[i].get().strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", name):
                raise ValueError(f"{a.reg}: parameter name '{name}' must be letters/digits/_")
            if name in seen:
                raise ValueError(f"duplicate parameter name '{name}'")
            seen.add(name)
            ptype = KIND_TYPE[a.kind]
            lst = self.plist_vars[i].get()
            lst = "" if lst == self.NONE else lst
            out[i] = ParamSpec(i, name, ptype, self._default(a, ptype, lst), lst)
        return out

    def _code_vars(self) -> list[CodeVar]:
        sel = self._selected()
        out: list[CodeVar] = []
        for row in self.cv_rows:
            info = row["info"]
            if not (info["owners"] & sel):
                continue
            default = row["def"].get().strip()
            as_input = row["in"].get()
            if as_input and not default:
                raise ValueError(f"${info['name']}: give a default value")
            lst = row["list"].get()
            out.append(CodeVar(info["name"], row["type"].get(), default,
                               "" if lst == self.NONE else lst, as_input, info["expr"]))
        return out

    def _param_dicts(self, params: dict[int, ParamSpec], cvs: list[CodeVar]) -> list[dict]:
        out = [p.to_dict() for p in params.values()]
        names = {p.name for p in params.values()}
        for cv in cvs:
            if cv.as_input:
                if cv.name in names:
                    raise ValueError(f"${cv.name} clashes with an editable register named '{cv.name}'")
                names.add(cv.name)
                out.append(ParamSpec(-1, cv.name, cv.type, cv.default, cv.items).to_dict())
        return out

    def on_edit_change(self) -> None:
        if self._ready:
            self.refresh()

    # ---------------------------------------------------------- bindings
    def _selected(self) -> set[str]:
        return {self.snap.buffers[i].name for i in self.lb.curselection()}

    def on_detect(self, quiet: bool = False) -> None:
        sel = self._selected()
        added = 0
        for i, a in enumerate(self.snap.args):
            if not self.edit_vars[i].get():
                continue
            width = TYPE_WIDTH[KIND_TYPE[a.kind]]
            want = (a.value & M64) & ((1 << (8 * width)) - 1)
            if want == 0:
                continue
            for b in self.snap.buffers:
                if b.name not in sel or not b.data:
                    continue
                hits = 0
                for off in range(0, len(b.data) - width + 1, width):
                    if int.from_bytes(b.data[off:off + width], "little") == want and hits < 8:
                        hits += 1
                        t = (b.name, off, i)
                        if t not in self.bindings:
                            self.bindings.append(t)
                            added += 1
        if not quiet:
            messagebox.showinfo("Cheats", f"Found {added} matching field(s) in the selected buffers.",
                                parent=self.win)
        self.refresh()

    def on_bind(self) -> None:
        try:
            off = int(self.m_off.get().strip() or "0", 0)
            idx = next(i for i, a in enumerate(self.snap.args)
                       if self.edit_vars[i].get() and self.pname_vars[i].get().strip() == self.m_par.get())
            if not self.m_buf.get():
                raise ValueError("pick a buffer")
        except StopIteration:
            messagebox.showerror("Cheats", "Tick a register as editable first and pick it here", parent=self.win)
            return
        except ValueError as exc:
            messagebox.showerror("Cheats", str(exc), parent=self.win)
            return
        t = (self.m_buf.get(), off, idx)
        if t not in self.bindings:
            self.bindings.append(t)
        self.refresh()

    def on_unbind(self) -> None:
        for i in sorted(self.bind_lb.curselection(), reverse=True):
            del self.bindings[i]
        self.refresh()

    # ----------------------------------------------------------- preview
    def _merge_gap(self) -> Optional[int]:
        if not self.merge.get():
            return None
        try:
            return max(0, int(self.merge_gap.get().strip() or "0", 0))
        except ValueError:
            raise ValueError("merge gap must be a number of bytes (e.g. 64)") from None

    def _steps(self, params: dict[int, ParamSpec], cvs: Optional[list[CodeVar]] = None) -> list[dict]:
        if cvs is None:
            cvs = self._code_vars()
        return build_steps(self.snap, self._selected(), self.aslr.get(), self.inc_call.get(),
                           self.inc_patch.get(), self.chk_orig.get(), self.free_after.get(),
                           params, self.bindings, cvs, self._merge_gap())

    def refresh(self) -> None:
        if not self._ready:
            return
        try:
            params = self._params()
            cvs = self._code_vars()
            steps = self._steps(params, cvs)
            text = json.dumps({"params": ensure_string_params(steps, self._param_dicts(params, cvs)),
                               "steps": steps}, indent=1)
        except ValueError as exc:
            params, text = {}, f"! {exc}"
        names = [p.name for p in params.values()]
        self.m_par_cb.configure(values=names)
        if self.m_par.get() not in names:
            self.m_par.set(names[0] if names else "")
        self.bind_lb.delete(0, "end")
        for bname, off, idx in self.bindings:
            p = params.get(idx)
            self.bind_lb.insert("end", f"@{bname}+0x{off:X}  <-  ${p.name if p else '(not editable)'}")
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", text)
        self.preview.configure(state="disabled")

    def on_save(self) -> None:
        tab = self.tab
        name = self.cheat_name.get().strip()
        try:
            params = self._params()
            cvs = self._code_vars()
            steps = self._steps(params, cvs)
            param_dicts = ensure_string_params(steps, self._param_dicts(params, cvs))
        except ValueError as exc:
            messagebox.showerror("Cheats", str(exc), parent=self.win)
            return
        if not name:
            messagebox.showerror("Cheats", "Give the cheat a name", parent=self.win)
            return
        if not steps:
            messagebox.showerror("Cheats", "Nothing to record - enable the call, a buffer or hex edits",
                                 parent=self.win)
            return
        choice = self.game_choice.get()
        try:
            if choice == self.NEW:
                tid = self.title_id.get().strip().upper()
                gname = self.game_name.get().strip() or tid or "New game"
                path = tab.folder / f"{re.sub(r'[^A-Za-z0-9_.-]+', '_', tid or gname).strip('_')}.json"
                if path.exists():
                    raise ValueError(f"{path.name} already exists - pick it in 'Save into'")
                game = Game(name=gname, title_id=tid, process=self.snap.proc_name, path=path)
            else:
                game = tab.games[[f"{g.name} [{g.title_id}]" for g in tab.games].index(choice)]
            base, n = name, 1
            while any(c.name == name for c in game.cheats):
                n += 1
                name = f"{base} {n}"
            cheat = Cheat(name=name, description=self.desc.get().strip(), mode=self.mode.get(),
                          steps=steps, params=param_dicts)
            game.cheats.append(cheat)
            game.save()
        except Exception as exc:
            messagebox.showerror("Cheats", str(exc), parent=self.win)
            return
        key = (str(game.path), cheat.name)
        tab.reload()
        tab._fill(select=key)
        tab.app.log_line(f"recorded cheat '{cheat.name}' ({len(steps)} steps, {len(param_dicts)} input(s)) "
                         f"into {game.path.name}")
        self.win.destroy()
