"""Cheats tab for the ps5debug-NG GUI (stdlib Tk)."""

from __future__ import annotations

import json
import re
import shutil
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Optional

import asmgen
from cheat_recorder import ArgSnap, RecordDialog, collect
from cheats import Cheat, CheatError, Game, execute, load_games, parse_param
from items import SearchCombobox
from scrollable import fit_geometry
import theme  # noqa: E402

HELP = """\
CHEAT FILE FORMAT  (ps5cheat/1, JSON, one file per game in ./cheats)

{
  "format": "ps5cheat/1",
  "game": "Game Name", "title_id": "PPSA01234", "version": "01.000.000",
  "content_id": "UP0000-PPSA01234_00-GAMENAME00000000",   (optional)
  "process": "eboot.bin", "author": "you",
  (title_id / version / content_id: press "From console" with the game running - the app
   version comes from the game's param.sfo, 01.03 on PS4, 01.000.000 on PS5;
   files are named <TITLEID>_<VERSION>.json, like GoldHEN / ShnExt cheat files)
  "cheats": [
    { "name": "Infinite Health", "mode": "toggle" | "once",
      "description": "...", "steps": [ ... ], "off": [ ... ] }
  ]
}

EXPRESSIONS (addresses / values)
  0x10  123  -5        numbers          @buf0     remote buffer address
  $var                 script variable  rax       last call result
  module(eboot.bin)    module base (ASLR-safe), module(main) = lowest exec map
  [ expr ]             dereference u64  (pointer chains)
  + - *                e.g. [[module(eboot.bin)+0x4A1C00]+0x20]+0x1C4

PARAMS (inputs shown when the cheat runs; use as $name anywhere)
  "params":[{"name":"item","label":"Item","type":"u32",
             "default":"Health Potion","items":"my_items"}]   items = file in cheats/items/
  {"op":"call","rip":EXPR,"args":["@buf0",{"type":"u32","value":"$item"}]}
  {"op":"write","addr":"@buf0+0x10","type":"u32","value":"$item"}
  Item files: {"Health Potion": 1001, "Mega Sword": "0x2F3"}

TYPES  u8 i8 u16 i16 u32 i32 u64 i64 ptr f32 f64 utf8 utf16 hex

STEPS
  {"op":"alloc","name":"buf0","size":256,"prot":"rw",
        "init":{"type":"utf8","value":"hello"}}      (reuses buf if it exists)
  {"op":"free","name":"buf0"}
  {"op":"write","addr":EXPR,"type":"u32","value":"999"}
  {"op":"patch","addr":EXPR,"type":"hex","value":"90 90"}   (original saved,
        restored automatically when a toggle cheat is disabled)
  {"op":"read","addr":EXPR,"type":"u32","store":"hp"}
  {"op":"call","rip":EXPR,"args":[EXPR, {"type":"f32","value":1.5}, ...],
        "store":"result"}                            (up to 6 args)
  {"op":"protect","addr":EXPR,"size":EXPR,"prot":"rwx"}
  {"op":"set","var":"x","value":EXPR}
  {"op":"check","addr":EXPR,"type":"hex","value":"48 89 5C"}  (abort if differs)
  {"op":"check","addr":EXPR,"type":"u32","equals":100}
  {"op":"log","text":"hello","value":EXPR}
  {"op":"sleep","ms":250}
  {"op":"code","name":"gadget","asm":"mov [rdi], rsi\nret","size":32,"prot":"rx",
        "align":16,"auto_ret":true}
        Assembles x86-64 asm (keystone) into a buffer and allocates/reuses it,
        same as 'alloc'; reference it with @gadget (e.g. as a call's "rip").
        Inside "asm", {expr} is any cheat expression (see above), substituted
        as a hex literal before assembling: {@buf0}  {module(eboot.bin)+0x10}
        {$item}. If the code doesn't end in ret/jmp, 'ret' is appended
        automatically. "size" pads with NOPs (default: next 16-byte
        multiple). Labels and local jumps work normally.
        Use the "Insert code step..." button for a text editor with a live
        assemble preview instead of typing this by hand.
  {"op":"repeat","count":3,"delay_ms":100,"steps":[ ... ]}

You normally don't write this by hand: set everything up in the Caller / Hex
tabs and press 'Record cheat from Caller tab...'.


"""


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "game"


class CheatsTab:
    def __init__(self, parent: ttk.Frame, app, make_buffer, folder: Path) -> None:
        self.app = app
        self.make_buffer = make_buffer
        self.folder = folder
        self.games: list[Game] = []
        self.iid_map: dict[str, tuple[Game, Optional[int]]] = {}
        self.enabled: set[tuple[str, str]] = set()
        self.undo: dict[tuple[str, str], list] = {}
        self.cur: Optional[tuple[Game, Optional[int]]] = None
        self.verify = tk.BooleanVar(value=True)
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self._fill())
        self.param_text: dict[tuple, str] = {}
        self.info_var = tk.StringVar(value="Select a cheat")
        self.desc_var = tk.StringVar()
        self._build(parent)
        app.items.on_change.append(self._build_params)

    # ------------------------------------------------------------------ UI
    def _build(self, parent: ttk.Frame) -> None:
        body = ttk.Panedwindow(parent, orient="horizontal")
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body, padding=4)
        right = ttk.Frame(body, padding=4)
        body.add(left, weight=1)
        body.add(right, weight=2)

        srow = ttk.Frame(left)
        srow.pack(fill="x")
        ttk.Label(srow, text="Search").pack(side="left")
        ttk.Entry(srow, textvariable=self.search).pack(side="left", fill="x", expand=True, padx=4)

        self.tree = ttk.Treeview(left, columns=("state",), show="tree headings", height=18)
        self.tree.heading("#0", text="Game / Cheat")
        self.tree.heading("state", text="State")
        self.tree.column("#0", width=300)
        self.tree.column("state", width=60, stretch=False, anchor="center")
        self.tree.tag_configure("on", foreground=theme.c("ok"))
        self.tree.pack(fill="both", expand=True, pady=4)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda _e: self.on_run())

        lb = ttk.Frame(left)
        lb.pack(fill="x")
        ttk.Button(lb, text="Reload", command=self.reload).pack(side="left", padx=2)
        ttk.Button(lb, text="Import file...", command=self.on_import).pack(side="left", padx=2)
        ttk.Button(lb, text="New game", command=self.on_new_game).pack(side="left", padx=2)
        ttk.Button(lb, text="New cheat", command=self.on_new_cheat).pack(side="left", padx=2)
        ttk.Button(lb, text="Delete", command=self.on_delete).pack(side="left", padx=2)

        ttk.Label(right, textvariable=self.info_var, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(right, textvariable=self.desc_var, wraplength=700).pack(anchor="w", pady=(0, 4))
        self.param_holder = ttk.Frame(right)
        self.param_holder.pack(fill="x", pady=(0, 4))

        rb = ttk.Frame(right)
        rb.pack(fill="x")
        ttk.Button(rb, text="Run / Toggle", command=self.on_run).pack(side="left", padx=2)
        ttk.Button(rb, text="Apply (keep on)", command=lambda: self.on_run(force_on=True)).pack(side="left", padx=2)
        ttk.Button(rb, text="Disable", command=lambda: self.on_run(force_off=True)).pack(side="left", padx=2)
        ttk.Checkbutton(rb, text="verify title id", variable=self.verify).pack(side="left", padx=10)
        ttk.Button(rb, text="Find game process", command=self.on_find_process).pack(side="left", padx=2)

        rec = ttk.Frame(right)
        rec.pack(fill="x", pady=(6, 0))
        ttk.Button(rec, text="Record cheat from Caller tab...", command=self.on_record).pack(side="left", padx=2)
        ttk.Label(rec, text="captures RIP, args, buffers (+contents), hex edits; 'edit'-ticked regs become inputs").pack(
            side="left", padx=6)

        eb = ttk.Frame(right)
        eb.pack(fill="x", pady=(6, 2))
        ttk.Button(eb, text="Save edits", command=self.on_save).pack(side="left", padx=2)
        ttk.Button(eb, text="Insert Caller call step", command=self.on_insert_call).pack(side="left", padx=2)
        ttk.Button(eb, text="Insert code step...", command=self.on_code_dialog).pack(side="left", padx=2)
        ttk.Button(eb, text="Format help", command=self.on_help).pack(side="left", padx=2)

        wrap = ttk.Frame(right)
        wrap.pack(fill="both", expand=True)
        self.editor = tk.Text(wrap, wrap="none", font=("Consolas", 10), undo=True)
        ys = ttk.Scrollbar(wrap, orient="vertical", command=self.editor.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=self.editor.xview)
        self.editor.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.editor.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)

    # ------------------------------------------------------------ loading
    def reload(self) -> None:
        self.games, errors = load_games(self.folder)
        for e in errors:
            self.app.log_line(f"cheat file error: {e}")
        self._fill()
        total = sum(len(g.cheats) for g in self.games)
        self.app.log_line(f"loaded {len(self.games)} game file(s), {total} cheat(s)")

    def _key(self, game: Game, cheat: Cheat) -> tuple[str, str]:
        return (str(game.path), cheat.name)

    def _fill(self, select: Optional[tuple[str, str]] = None) -> None:
        q = self.search.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        self.iid_map.clear()
        pick = None
        for gi, g in enumerate(self.games):
            game_hit = q in f"{g.name} {g.title_id}".lower()
            kids = [(ci, c) for ci, c in enumerate(g.cheats) if not q or game_hit or q in c.name.lower()]
            if q and not game_hit and not kids:
                continue
            giid = f"g{gi}"
            label = f"{g.name}  [{g.title_id or '?'}]" + (f"  v{g.version}" if g.version else "")
            self.tree.insert("", "end", iid=giid, text=label, open=True)
            self.iid_map[giid] = (g, None)
            for ci, c in kids:
                iid = f"g{gi}:{ci}"
                on = self._key(g, c) in self.enabled
                self.tree.insert(giid, "end", iid=iid, text=c.name,
                                 values=("ON" if on else "",), tags=("on",) if on else ())
                self.iid_map[iid] = (g, ci)
                if select == self._key(g, c):
                    pick = iid
        if pick:
            self.tree.selection_set(pick)

    def _mark(self, game: Game, ci: int) -> None:
        for iid, (g, idx) in self.iid_map.items():
            if g is game and idx == ci:
                on = self._key(game, game.cheats[ci]) in self.enabled
                self.tree.set(iid, "state", "ON" if on else "")
                self.tree.item(iid, tags=("on",) if on else ())

    # ---------------------------------------------------------- selection
    def _selection(self) -> Optional[tuple[Game, Optional[int]]]:
        sel = self.tree.selection()
        return self.iid_map.get(sel[0]) if sel else None

    def _on_select(self, _e=None) -> None:
        sel = self._selection()
        self.cur = sel
        self.editor.delete("1.0", "end")
        if not sel:
            self._build_params()
            return
        g, ci = sel
        if ci is None:
            self.info_var.set(f"{g.name}  [{g.title_id}]  v{g.version}  {g.author}")
            self.desc_var.set(f"{len(g.cheats)} cheat(s)  -  {g.path.name if g.path else ''}")
            self.editor.insert("1.0", json.dumps(g.meta_dict(full=True), indent=2))
        else:
            c = g.cheats[ci]
            self.info_var.set(f"{g.name}  >  {c.name}   ({c.mode})")
            self.desc_var.set(c.description)
            self.editor.insert("1.0", json.dumps(c.to_dict(), indent=2))
        self._build_params()

    # --------------------------------------------------------- parameters
    def _lookup_for(self, p: dict):
        lst = p.get("items", "")
        return (lambda t: self.app.items.lookup(lst, t)) if lst else None

    def _build_params(self) -> None:
        for w in self.param_holder.winfo_children():
            w.destroy()
        sel = self._selection()
        if not sel or sel[1] is None:
            return
        game, ci = sel
        cheat = game.cheats[ci]
        if not cheat.params:
            return
        key = self._key(game, cheat)
        box = ttk.LabelFrame(self.param_holder, text="Inputs", padding=6)
        box.pack(fill="x")
        for r, p in enumerate(cheat.params):
            name, ptype, lst = p["name"], str(p.get("type", "u32")), p.get("items", "")
            ttk.Label(box, text=f"{p.get('label') or name}  ({ptype})").grid(row=r, column=0, sticky="w", padx=(0, 8))
            var = tk.StringVar(value=self.param_text.get((key, name), str(p.get("default", ""))))
            var.trace_add("write", lambda *_, k=(key, name), v=var: self.param_text.__setitem__(k, v.get()))
            entries = self.app.items.items(lst) if lst else {}
            if entries:
                w = SearchCombobox(box, textvariable=var, width=38)
                w.set_values(sorted(entries, key=str.lower))
            else:
                w = ttk.Entry(box, textvariable=var, width=38)
            w.grid(row=r, column=1, sticky="we", pady=1)
            info = ttk.Label(box, text="", width=34)
            info.grid(row=r, column=2, sticky="w", padx=8)
            var.trace_add("write", lambda *_, p=p, v=var, l=info: self._show_resolved(p, v, l))
            self._show_resolved(p, var, info)
            if lst and not entries:
                info.configure(text=f"item list '{lst}' not loaded - type a number")
        box.columnconfigure(1, weight=1)
        if not any(p.get("items") for p in cheat.params):
            ttk.Label(box, text="Enter a value, then Run / Toggle (or Apply to change it while on).").grid(
                row=len(cheat.params), column=0, columnspan=3, sticky="w", pady=(4, 0))

    def _show_resolved(self, p: dict, var: tk.StringVar, label: ttk.Label) -> None:
        try:
            v = parse_param(str(p.get("type", "u32")), var.get(), self._lookup_for(p))
            label.configure(text=f"= 0x{v:X} ({v})" if isinstance(v, int) else f"= {v}", foreground="")
        except CheatError as exc:
            label.configure(text=str(exc), foreground=theme.c("danger"))

    def _collect_params(self, cheat: Cheat, key: tuple) -> dict:
        out = {}
        for p in cheat.params:
            text = self.param_text.get((key, p["name"]), str(p.get("default", "")))
            try:
                out[p["name"]] = parse_param(str(p.get("type", "u32")), text, self._lookup_for(p))
            except CheatError as exc:
                raise ValueError(f"{p.get('label') or p['name']}: {exc}") from None
        return out

    # ------------------------------------------------------------ actions
    def on_run(self, force_off: bool = False, force_on: bool = False) -> None:
        sel = self._selection()
        if not sel or sel[1] is None:
            messagebox.showerror("Cheats", "Select a cheat first")
            return
        game, ci = sel
        cheat = game.cheats[ci]
        key = self._key(game, cheat)
        off = force_off or (cheat.mode == "toggle" and key in self.enabled and not force_on)
        if off and cheat.mode == "toggle" and key not in self.enabled and not cheat.off:
            self.app.log_line(f"'{cheat.name}' is not enabled")
            return
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return
        undo = self.undo.setdefault(key, [])
        verify = self.verify.get()
        try:
            params = self._collect_params(cheat, key)
        except ValueError as exc:
            messagebox.showerror("Cheats", str(exc))
            return
        root, app = self.app.root, self.app

        def log(msg: str) -> None:
            root.after(0, lambda m=msg: app.log_line(m))

        def work() -> None:
            root.after(0, lambda: app.log_line(f"{'disable' if off else 'run'} cheat: {cheat.name}"))
            try:
                execute(cheat, game, app.client, app.state, pid, self.make_buffer,
                        log, undo, off=off, verify_title=verify, params=params)
            except CheatError as exc:
                raise RuntimeError(str(exc)) from exc
            if cheat.mode == "toggle":
                (self.enabled.discard if off else self.enabled.add)(key)
            rax = app.state.last_rax
            root.after(0, lambda: self._after_run(game, ci, rax, off))

        app._run_bg(work, f"Cheat: {cheat.name}...")

    def _after_run(self, game: Game, ci: int, rax: int, off: bool) -> None:
        self._mark(game, ci)
        self.app._refresh_buf_tree()
        self.app.rax_var.set(f"RAX = 0x{rax:X}")
        self.app.log_line(f"done: {game.cheats[ci].name} ({'off' if off else 'ok'})")

    def on_find_process(self) -> None:
        sel = self._selection()
        if not sel:
            messagebox.showerror("Cheats", "Select a game or cheat first")
            return
        game = sel[0]
        if not game.title_id and not game.process:
            messagebox.showerror("Cheats", "Game has no title_id or process set")
            return
        app, root = self.app, self.app.root

        def work() -> None:
            found = None
            for p in app.client.list_processes():
                if game.process and p.name.lower() == game.process.lower() and not game.title_id:
                    found = p
                    break
                try:
                    info = app.client.proc_info(p.pid)
                except Exception:
                    continue
                if game.title_id and info.titleid.strip().upper() == game.title_id.upper():
                    found = p
                    break
            if not found:
                raise RuntimeError(f"{game.name} ({game.title_id}) is not running")
            root.after(0, lambda: (app.pid_var.set(str(found.pid)),
                                   app.log_line(f"found {game.name}: pid={found.pid} ({found.name})")))

        app._run_bg(work, "Searching processes...")

    def on_record(self) -> None:
        app = self.app
        try:
            pid = app._pid()
            rip_text = app.rip_var.get().strip()
            rip = app.eval_int(rip_text) if rip_text else 0
            args = []
            for reg in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                kind, text = app.arg_kind[reg].get(), app.arg_val[reg].get()
                value = app.eval_arg(kind, text)
                picked = app.arg_item_pick.get(reg)
                lst = ""
                if picked and app.items.lookup(picked[0], picked[1]) == app.eval_int(text):
                    lst = picked[0]
                args.append(ArgSnap(reg, kind, text, value, app.arg_edit[reg].get(), lst))
            patches = []
            view = app.hex_view
            if not view.empty():
                for addr, new in view.patches():
                    off = addr - view.base
                    patches.append((addr, new, bytes(view.orig[off:off + len(new)])))
        except Exception as exc:
            app._fail(exc)
            return
        if not rip and not patches and not app.state.buffers:
            messagebox.showerror("Cheats", "Set up a call (RIP), buffers or hex edits in the other tabs first")
            return
        root = app.root

        def work() -> None:
            snap = collect(app, pid, rip, args, patches)
            root.after(0, lambda: RecordDialog(self, snap))

        app._run_bg(work, "Capturing Caller state...")

    def on_insert_call(self) -> None:
        app = self.app
        regs = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        args: list = []
        for reg in regs:
            kind, val = app.arg_kind[reg].get(), app.arg_val[reg].get().strip() or "0"
            if kind == "float bits":
                args.append({"type": "f32", "value": float(val)})
            elif kind == "double bits":
                args.append({"type": "f64", "value": float(val)})
            else:
                args.append(val)
        while args and args[-1] == "0":
            args.pop()
        step = {"op": "call", "rip": app.rip_var.get().strip() or "0", "args": args, "store": "ret"}
        self.editor.insert("insert", json.dumps(step) + ",\n")

    def on_save(self) -> None:
        if not self.cur:
            return
        game, ci = self.cur
        try:
            data = json.loads(self.editor.get("1.0", "end-1c"))
            if ci is None:
                fixed = game.apply_meta(data)
                if fixed:
                    self.app.log_line(f"{game.name}: " + "; ".join(fixed))
                sel_key = None
            else:
                old = game.cheats[ci]
                new = Cheat.from_dict(data)
                if new.name != old.name:
                    self.enabled.discard(self._key(game, old))
                game.cheats[ci] = new
                sel_key = self._key(game, new)
            game.save()
        except Exception as exc:
            messagebox.showerror("Cheats", f"Not saved: {exc}")
            return
        self._fill(select=sel_key)
        self.app.log_line(f"saved {game.path.name if game.path else game.name}")

    def on_new_game(self) -> None:
        name = simpledialog.askstring("New game", "Game name:", parent=self.app.root)
        if not name:
            return
        tid = simpledialog.askstring("New game", "Title ID (e.g. PPSA01234):", parent=self.app.root) or ""
        ver = simpledialog.askstring("New game", "App version (01.03 on PS4, 01.000.000 on PS5):",
                                     parent=self.app.root) or ""
        import game_ids  # noqa: PLC0415
        d, _fixed = game_ids.normalize({"game": name, "title_id": tid.strip(), "version": ver.strip()})
        path = game_ids.library_path(self.folder, d["title_id"], d["version"], name)
        g = Game(name=name, title_id=d["title_id"], version=d["version"], process=d["process"], path=path)
        g.cheats.append(self._template())
        g.save()
        self.reload()

    def on_new_cheat(self) -> None:
        sel = self._selection()
        if not sel:
            messagebox.showerror("Cheats", "Select a game first")
            return
        game = sel[0]
        c = self._template()
        n = 1
        while any(x.name == c.name for x in game.cheats):
            n += 1
            c.name = f"New cheat {n}"
        game.cheats.append(c)
        game.save()
        self._fill(select=self._key(game, c))

    @staticmethod
    def _template() -> Cheat:
        return Cheat(
            name="New cheat", description="", mode="toggle",
            steps=[{"op": "patch", "addr": "module(eboot.bin)+0x0", "type": "hex", "value": "90 90"}],
        )

    def on_delete(self) -> None:
        sel = self._selection()
        if not sel or sel[1] is None:
            messagebox.showerror("Cheats", "Select a cheat to delete")
            return
        game, ci = sel
        if not messagebox.askyesno("Delete", f"Delete '{game.cheats[ci].name}'?"):
            return
        del game.cheats[ci]
        game.save()
        self._fill()

    def on_import(self) -> None:
        paths = filedialog.askopenfilenames(title="Import cheat file(s)",
                                            filetypes=[("Cheat JSON", "*.json"), ("All", "*.*")])
        for p in paths:
            try:
                Game.from_dict(json.loads(Path(p).read_text(encoding="utf-8")))
                self.folder.mkdir(parents=True, exist_ok=True)
                shutil.copy(p, self.folder / Path(p).name)
            except Exception as exc:
                messagebox.showerror("Cheats", f"{Path(p).name}: {exc}")
        if paths:
            self.reload()

    def on_code_dialog(self) -> None:
        CodeStepDialog(self)

    def on_help(self) -> None:
        win = tk.Toplevel(self.app.root)
        win.title("Cheat format")
        fit_geometry(win, 780, 640)
        t = tk.Text(win, wrap="none", font=("Consolas", 10))
        t.insert("1.0", HELP)
        t.configure(state="disabled")
        t.pack(fill="both", expand=True)


class CodeStepDialog:
    """Assembly editor for the 'code' step: write asm, see bytes live, insert."""

    EXPR_HELP = (
        "{expr} inside the asm is substituted with a hex literal before assembling:\n"
        "  {@buf0}               address of an allocated buffer\n"
        "  {module(eboot.bin)+0x10}   ASLR-safe module address\n"
        "  {$item}               a cheat parameter / stored variable\n"
        "ret is appended automatically if the code doesn't already end in one."
    )

    def __init__(self, tab) -> None:
        self.tab = tab
        win = tk.Toplevel(tab.app.root)
        self.win = win
        win.title("Insert code step")
        fit_geometry(win, 760, 560)
        win.transient(tab.app.root)

        top = ttk.Frame(win, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Buffer name").pack(side="left")
        self.name_var = tk.StringVar(value="gadget")
        ttk.Entry(top, textvariable=self.name_var, width=14).pack(side="left", padx=4)
        ttk.Label(top, text="Size (blank = auto)").pack(side="left")
        self.size_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.size_var, width=10).pack(side="left", padx=4)
        ttk.Label(top, text="Prot").pack(side="left")
        self.prot_var = tk.StringVar(value="rx")
        ttk.Combobox(top, textvariable=self.prot_var, values=("rx", "rwx", "r", "rw"),
                     width=6, state="readonly").pack(side="left", padx=4)
        self.auto_ret = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="auto ret", variable=self.auto_ret).pack(side="left", padx=8)

        ttk.Label(win, text=self.EXPR_HELP, justify="left", padding=(8, 0)).pack(anchor="w")

        mid = ttk.Panedwindow(win, orient="vertical")
        mid.pack(fill="both", expand=True, padx=8, pady=6)
        asm_frame = ttk.LabelFrame(mid, text="Assembly (x86-64)")
        out_frame = ttk.LabelFrame(mid, text="Preview (unresolved {expr} shown as 0)")
        mid.add(asm_frame, weight=3)
        mid.add(out_frame, weight=1)

        self.asm = tk.Text(asm_frame, wrap="none", font=("Consolas", 11), undo=True, height=14)
        self.asm.pack(fill="both", expand=True)
        self.asm.insert("1.0", "; write asm here, e.g.\nmov dword ptr [rdi], 0x3F800000\n")
        self.asm.bind("<<Modified>>", self._on_modified)

        self.out = tk.Text(out_frame, wrap="word", font=("Consolas", 10), height=6, state="disabled")
        self.out.pack(fill="both", expand=True)

        btns = ttk.Frame(win, padding=8)
        btns.pack(fill="x")
        ttk.Button(btns, text="Assemble preview", command=self.on_preview).pack(side="left", padx=2)
        ttk.Button(btns, text="Insert step", command=self.on_insert).pack(side="left", padx=2)
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="left", padx=2)

        self.on_preview()

    def _on_modified(self, _e=None) -> None:
        self.asm.edit_modified(False)

    def _write_out(self, text: str, error: bool = False) -> None:
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text)
        self.out.tag_configure("err", foreground=theme.c("danger"))
        if error:
            self.out.tag_add("err", "1.0", "end")
        self.out.configure(state="disabled")

    def on_preview(self) -> None:
        code = self.asm.get("1.0", "end-1c")
        try:
            resolved = asmgen.substitute(code, lambda _e: 0)
            resolved = asmgen.ensure_ret(resolved, self.auto_ret.get())
            raw = asmgen.assemble(resolved)
            size = self.size_var.get().strip()
            data = asmgen.pad(raw, int(size, 0) if size else None)
            self._write_out(f"{len(raw)} bytes (padded to {len(data)})\n\n" + data.hex(" "))
        except asmgen.AsmError as exc:
            self._write_out(str(exc), error=True)
        except Exception as exc:
            self._write_out(f"error: {exc}", error=True)

    def on_insert(self) -> None:
        name = self.name_var.get().strip()
        if not name:
            messagebox.showerror("Cheats", "Give the code buffer a name", parent=self.win)
            return
        step: dict = {"op": "code", "name": name, "asm": self.asm.get("1.0", "end-1c").rstrip("\n")}
        size = self.size_var.get().strip()
        if size:
            step["size"] = int(size, 0)
        if self.prot_var.get() != "rx":
            step["prot"] = self.prot_var.get()
        if not self.auto_ret.get():
            step["auto_ret"] = False
        self.tab.editor.insert("insert", json.dumps(step) + ",\n")
        self.win.destroy()
