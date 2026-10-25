"""Cheat Editor tab: build and edit cheats. For just running them, see the
Cheats tab (cheats_play_tab.py) - both share one CheatsStore."""

from __future__ import annotations

import datetime
import json
import re
import shutil
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Optional

import asmgen
import cheat_formats
import cheat_pack
import cheat_tools
from bulk_items import BulkItemsDialog
from cheat_recorder import ArgSnap, RecordDialog, collect
from cheats import Cheat, Game
from cheats_store import CheatsStore
from items import SearchCombobox
from scrollable import ScrollFrame, fit_geometry
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

TEXT INPUTS (e.g. a player name written into a buffer)
  {"op":"alloc","name":"name","size":32,"prot":"rw",
        "init":{"type":"utf8","value":"{playername}"}}
  Any {identifier} inside a utf8/utf16 value (alloc init, write, patch) becomes
  a text input automatically when you Save edits. Works mixed with text:
  "Player: {playername}". Text longer than 'size' is rejected.
  Manual form: "params":[{"name":"playername","type":"string","default":"Bob"}]

TYPES  u8 i8 u16 i16 u32 i32 u64 i64 ptr f32 f64 utf8 utf16 hex

STEPS
  {"op":"alloc","name":"buf0","size":256,"prot":"rw",
        "init":{"type":"utf8","value":"hello"}}      (reuses buf if it exists)
  {"op":"free","name":"buf0"}
  {"op":"write","addr":EXPR,"type":"u32","value":"999"}
  {"op":"patch","addr":EXPR,"type":"hex","value":"90 90"}   (original saved,
        restored automatically when a toggle cheat is disabled)
  {"op":"read","addr":EXPR,"type":"u32","store":"hp"}
  {"op":"python","code":"ps5.write_u32('@stats', 99)"}   (Python with the ps5 API - edit with 'Python step…')
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
        automatically. Code that calls functions or writes [rsp+X] without
        reserving stack gets an automatic frame (sub rsp,N ... add rsp,N);
        "auto_frame": false turns that off. "size" pads with NOPs (default: next 16-byte
        multiple). Labels and local jumps work normally.
        Use the "Insert code step..." button for a text editor with a live
        assemble preview instead of typing this by hand. The Caller tab also
        has a "Quick code" panel for assembling and test-calling directly,
        without saving a cheat first.
  {"op":"repeat","count":3,"delay_ms":100,"steps":[ ... ]}
  {"op":"aob","pattern":"48 8B 05 ?? ?? ?? ?? 48 85 C0","store":"site","offset":0}
        Finds the bytes in the game's code (?? = any byte) and stores the address
        in $site - use it as "addr":"$site" in hook / patch / write steps, so the
        cheat survives game updates. Optional: "module":"main" (default) or a
        module name, "index":2 (2nd match), "data":true (search data, not code).
        Build one with the AOB bar in the Disassembler tab.
  {"op":"asmpatch","addr":"$site","asm":"jmp {@cave}\nnop"}
        Assembles at the target address (relative jumps work) and writes it;
        the original bytes come back when a toggle cheat is turned off.
  "near":"$site" on alloc / code: allocate within 2 GB of that address
        (needed for RIP-relative access and 5-byte jumps).
  {"op":"hook","name":"hk","addr":"module(eboot.bin)+0x55A010","orig":"8B 45 F8 90 90",
        "asm":"add eax, 100\nmov ecx, dword ptr [rip:module(eboot.bin)+0x4A1C00]","far":false}
        Code cave: replaces the instruction(s) at addr (bytes `orig`, checked first) by a jump
        to a cave running `asm`, then returns after them. Toggle off restores the original.
        Build it with right-click > Code cave... in the Disassembler tab.

You normally don't write this by hand: set everything up in the Caller / Hex
tabs and press 'Record cheat from Caller tab...'.

Running cheats day-to-day: use the Cheats tab, which shows just names and
on/off switches - this tab is for building and tweaking them.
"""


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "game"


class CheatsEditorTab:
    def __init__(self, parent: ttk.Frame, app, store: CheatsStore) -> None:
        self.app = app
        self.store = store
        self.iid_map: dict[str, tuple[Game, Optional[int]]] = {}
        self._closed: set[str] = set()                  # game files collapsed in the tree (kept on refresh)
        self.cur: Optional[tuple[Game, Optional[int]]] = None
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self._fill())
        self.info_var = tk.StringVar(value="Select a cheat")
        self.desc_var = tk.StringVar()
        self._build(parent)
        app.items.on_change.append(self._build_params)
        store.on_change(self._on_store_change)

    @property
    def games(self) -> list[Game]:
        return self.store.games

    @property
    def folder(self) -> Path:
        return self.store.folder

    # ------------------------------------------------------------------ UI
    def _build(self, parent: ttk.Frame) -> None:
        scroll = ScrollFrame(parent)
        scroll.pack(fill="both", expand=True)
        body = ttk.Panedwindow(scroll.body, orient="horizontal")
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body, padding=4)
        right = ttk.Frame(body, padding=4)
        body.add(left, weight=1)
        body.add(right, weight=2)

        prow = ttk.Frame(left)
        prow.pack(fill="x")
        ttk.Label(prow, text="Project").pack(side="left")
        self.proj_var = tk.StringVar()
        self.proj_box = ttk.Combobox(prow, textvariable=self.proj_var, state="readonly", width=20)
        self.proj_box.pack(side="left", fill="x", expand=True, padx=4)
        self.proj_box.bind("<<ComboboxSelected>>", self._on_project_pick)
        prow2 = ttk.Frame(left)
        prow2.pack(fill="x", pady=(3, 0))
        ttk.Button(prow2, text="New project\u2026", command=self.on_new_project).pack(side="left", padx=(0, 2))
        ttk.Button(prow2, text="Open project\u2026", command=self.on_open_project).pack(side="left", padx=2)
        ttk.Button(prow2, text="Show folder", command=self.on_show_project).pack(side="left", padx=2)
        self.proj_path = tk.StringVar()
        ttk.Label(left, textvariable=self.proj_path, foreground=theme.c("muted"), font=("Segoe UI", 8)).pack(
            anchor="w", pady=(1, 4))
        self._fill_projects()

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
        self.tree.bind("<Double-1>", self._on_double)
        self.tree.bind("<Button-3>", self._tree_menu)
        self.tree.bind("<<TreeviewOpen>>", lambda _e: self._remember_open(True))
        self.tree.bind("<<TreeviewClose>>", lambda _e: self._remember_open(False))

        lb = ttk.Frame(left)
        lb.pack(fill="x")
        ttk.Button(lb, text="Reload", command=self.reload).pack(side="left", padx=2)
        ttk.Button(lb, text="New game", command=self.on_new_game).pack(side="left", padx=2)
        ttk.Button(lb, text="New cheat", command=self.on_new_cheat).pack(side="left", padx=2)
        ttk.Button(lb, text="Delete", command=self.on_delete).pack(side="left", padx=2)
        ttk.Button(lb, text="Delete game", command=self.on_delete_game).pack(side="left", padx=2)
        lb2 = ttk.Frame(left)
        lb2.pack(fill="x", pady=(4, 0))
        ttk.Button(lb2, text="Import...", command=self.on_import).pack(side="left", padx=2)
        ttk.Button(lb2, text="Import folder...", command=self.on_import_folder).pack(side="left", padx=2)
        ttk.Button(lb2, text="Export...", command=self.on_export).pack(side="left", padx=2)
        ttk.Button(lb2, text="Copy code", command=self.on_copy_code).pack(side="left", padx=2)
        ttk.Button(lb2, text="Paste code...", command=self.on_paste_code).pack(side="left", padx=2)

        ttk.Label(right, textvariable=self.info_var, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(right, textvariable=self.desc_var, wraplength=700).pack(anchor="w", pady=(0, 4))
        self.param_holder = ttk.Frame(right)
        self.param_holder.pack(fill="x", pady=(0, 4))

        rb = ttk.Frame(right)
        rb.pack(fill="x")
        ttk.Label(rb, text="Test:").pack(side="left")
        ttk.Button(rb, text="Run / Toggle", command=self.on_run).pack(side="left", padx=2)
        ttk.Button(rb, text="Apply (keep on)", command=lambda: self.on_run(force_on=True)).pack(side="left", padx=2)
        ttk.Button(rb, text="Disable", command=lambda: self.on_run(force_off=True)).pack(side="left", padx=2)
        ttk.Checkbutton(rb, text="verify title id", variable=self.store.verify).pack(side="left", padx=10)
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
        ttk.Button(eb, text="Python step…", command=self.on_python_step).pack(side="left", padx=2)
        ttk.Button(eb, text="Check & fix", command=self.on_check_fix).pack(side="left", padx=2)
        ttk.Button(eb, text="Format help", command=self.on_help).pack(side="left", padx=2)

        wrap = ttk.Frame(right)
        wrap.pack(fill="both", expand=True)
        wrap.configure(height=360)
        wrap.pack_propagate(False)
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
        self.store.reload()  # triggers _on_store_change -> _fill()

    def _on_store_change(self) -> None:
        if hasattr(self, "proj_box"):
            self._fill_projects()
        self._fill(select=self._current_key())
        self._build_params()

    def _current_key(self):
        if not self.cur:
            return None

        game, ci = self.cur

        # ci is None while a game (not a cheat) is selected
        if ci is None or ci < 0 or ci >= len(game.cheats):
            return None

        return self.store.key(game, game.cheats[ci])

    def _fill(self, select=None) -> None:
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
            self.tree.insert("", "end", iid=giid, text=label, open=bool(q) or str(g.path) not in self._closed)
            self.iid_map[giid] = (g, None)
            for ci, c in kids:
                iid = f"g{gi}:{ci}"
                on = self.store.is_enabled(g, c)
                self.tree.insert(giid, "end", iid=iid, text=c.name,
                                 values=("ON" if on else "",), tags=("on",) if on else ())
                self.iid_map[iid] = (g, ci)
                if select == self.store.key(g, c):
                    pick = iid
        if pick:
            self.tree.selection_set(pick)

    def _remember_open(self, is_open: bool) -> None:
        iid = self.tree.focus()
        g = self.iid_map.get(iid, (None, 0))
        if g[0] is not None and g[1] is None:
            (self._closed.discard if is_open else self._closed.add)(str(g[0].path))

    def _on_double(self, event) -> Optional[str]:
        """Double-click a cheat = run / toggle it.  On a game row it only opens / closes the game."""
        row = self.tree.identify_row(event.y)
        g = self.iid_map.get(row)
        if g and g[1] is not None:
            self.on_run()
        return None

    # ---------------------------------------------------------- projects
    def _fill_projects(self) -> None:
        import projects                                   # noqa: PLC0415
        self._proj_paths = self.app.recent_projects() if hasattr(self.app, "recent_projects") else [self.folder]
        if self.folder not in self._proj_paths:
            self._proj_paths.insert(0, self.folder)
        labels = []
        for p in self._proj_paths:
            nm = projects.info(p)["name"]
            labels.append(nm if nm not in labels else f"{nm} ({p.parent.name})")
        self.proj_box.configure(values=labels)
        cur = self._proj_paths.index(self.folder)
        self.proj_var.set(labels[cur])
        games, lists = projects.counts(self.folder)
        self.proj_path.set(f"{self.folder}   \u00b7 {games} game file(s), {lists} item list(s)")

    def _on_project_pick(self, _e=None) -> None:
        i = self.proj_box.current()
        if 0 <= i < len(self._proj_paths) and self._proj_paths[i] != self.folder:
            self.cur = None
            self.app.switch_project(self._proj_paths[i])
        self._fill_projects()

    def on_new_project(self) -> None:
        import projects                                   # noqa: PLC0415
        win = tk.Toplevel(self.app.root)
        win.title("New cheat project")
        win.transient(self.app.root)
        win.resizable(False, False)
        f = ttk.Frame(win, padding=12)
        f.pack(fill="both", expand=True)
        name_v = tk.StringVar()
        where_v = tk.StringVar(value=str(Path(self.app.settings.get("projects_parent") or
                                              (Path.home() / "Documents" / "PS5 cheat projects"))))
        author_v = tk.StringVar(value=self.app.author() if hasattr(self.app, "author") else "")
        notes_v = tk.StringVar()
        rows = (("Project name", name_v), ("Create in", where_v), ("Author", author_v), ("Notes", notes_v))
        for r, (label, var) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=2)
            ttk.Entry(f, textvariable=var, width=46).grid(row=r, column=1, sticky="we", padx=(6, 0), pady=2)
        ttk.Button(f, text="Browse...", command=lambda: where_v.set(
            filedialog.askdirectory(parent=win, initialdir=where_v.get(), title="Folder for the new project")
            or where_v.get())).grid(row=1, column=2, padx=(4, 0))
        info = tk.StringVar()
        ttk.Label(f, textvariable=info, foreground=theme.c("muted"), justify="left", wraplength=470).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))

        def preview(*_a) -> None:
            nm = name_v.get().strip()
            p = Path(where_v.get().strip() or ".") / projects.slug(nm or "name")
            info.set(f"Creates {p}\n  game cheat files (TITLEID.json) in the folder itself\n"
                     f"  items\\    item ID lists for cheat inputs\n  exports\\  exported .shn / .mc4 / .json / .ps5c")
        for v in (name_v, where_v):
            v.trace_add("write", preview)
        preview()
        copy_v = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Copy the item ID lists of the current project", variable=copy_v).grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(6, 0))

        def ok() -> None:
            nm = name_v.get().strip()
            if not nm:
                messagebox.showerror("New project", "Enter a project name", parent=win)
                return
            try:
                p = projects.create(Path(where_v.get().strip()), nm, author_v.get().strip(), notes_v.get().strip())
                if copy_v.get():
                    for src in (self.folder / "items").glob("*.json"):
                        shutil.copy(src, p / "items" / src.name)
            except Exception as exc:
                messagebox.showerror("New project", str(exc), parent=win)
                return
            self.app.settings["projects_parent"] = where_v.get().strip()
            win.destroy()
            self.cur = None
            self.app.switch_project(p)
            self._fill_projects()

        b = ttk.Frame(f)
        b.grid(row=6, column=0, columnspan=3, sticky="e", pady=(10, 0))
        ttk.Button(b, text="Create", style="Accent.TButton", command=ok).pack(side="left", padx=2)
        ttk.Button(b, text="Cancel", command=win.destroy).pack(side="left", padx=2)
        win.bind("<Return>", lambda _e: ok())
        win.bind("<Escape>", lambda _e: win.destroy())
        win.grab_set()

    def on_open_project(self) -> None:
        d = filedialog.askdirectory(title="Open a cheat project folder (or any folder with cheat .json files)",
                                    initialdir=str(self.folder.parent))
        if d:
            self.cur = None
            self.app.switch_project(Path(d))
            self._fill_projects()

    def on_show_project(self) -> None:
        import os, subprocess, sys                       # noqa: E401, PLC0415
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(self.folder))          # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(self.folder)])
        except Exception as exc:
            messagebox.showerror("Project", f"Could not open {self.folder}: {exc}")

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
            self.info_var.set(
                f"{g.name} [{g.title_id}] v{g.version} {g.author}"
            )
            self.desc_var.set(
                f"{len(g.cheats)} cheat(s) - {g.path.name if g.path else ''}"
            )
            self.editor.insert(
                "1.0",
                json.dumps(g.meta_dict(full=True), indent=2)
            )

        else:
            # Make sure the stored Treeview index is still valid
            if ci < 0 or ci >= len(g.cheats):
                self.cur = None
                self._build_params()
                return

            c = g.cheats[ci]

            self.info_var.set(
                f"{g.name} > {c.name} ({c.mode})"
            )
            self.desc_var.set(c.description)
            self.editor.insert(
                "1.0",
                json.dumps(c.to_dict(), indent=2)
            )

        self._build_params()

    # --------------------------------------------------------- parameters
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
        key = self.store.key(game, cheat)
        box = ttk.LabelFrame(self.param_holder, text="Inputs", padding=6)
        box.pack(fill="x")
        for r, p in enumerate(cheat.params):
            name, ptype, lst = p["name"], str(p.get("type", "u32")), p.get("items", "")
            ttk.Label(box, text=f"{p.get('label') or name}  ({ptype})").grid(row=r, column=0, sticky="w", padx=(0, 8))
            var = tk.StringVar(value=self.store.param_var_text(key, p))
            var.trace_add("write", lambda *_, k=key, n=name, v=var: self.store.set_param_text(k, n, v.get()))
            entries = self.app.items.items(lst) if lst else {}
            if entries:
                w = SearchCombobox(box, textvariable=var, width=38)
                w.set_values(sorted(entries, key=str.lower))
            else:
                w = ttk.Entry(box, textvariable=var, width=38)
            w.grid(row=r, column=1, sticky="we", pady=1)
            info = ttk.Label(box, text="", width=34)
            info.grid(row=r, column=2, sticky="w", padx=8)
            if entries:
                ttk.Button(box, text=f"Add all items ({len(entries)})...",
                           command=lambda g=game, c=cheat, pp=p: BulkItemsDialog(
                               self.app, self.store, g, c, pp)).grid(row=r, column=3, padx=4)
            var.trace_add("write", lambda *_, p=p, v=var, l=info: self._show_resolved(p, v, l))
            self._show_resolved(p, var, info)
            if lst and not entries:
                info.configure(text=f"item list '{lst}' not loaded - type a number")
        box.columnconfigure(1, weight=1)

    def _show_resolved(self, p: dict, var: tk.StringVar, label: ttk.Label) -> None:
        text, is_err = self.store.resolved(p, var.get())
        label.configure(text=text if is_err else f"= {text}", foreground=theme.c("danger") if is_err else "")

    # ------------------------------------------------------------ actions
    def on_run(self, force_off: bool = False, force_on: bool = False) -> None:
        sel = self._selection()
        if not sel or sel[1] is None:
            messagebox.showerror("Cheats", "Select a cheat first")
            return
        game, ci = sel
        self.store.run(game, game.cheats[ci], force_off=force_off, force_on=force_on)

    def on_find_process(self) -> None:
        sel = self._selection()
        if not sel:
            messagebox.showerror("Cheats", "Select a game or cheat first")
            return
        self.store.find_process(sel[0])

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
            view_snap = None
            view = app.hex_view
            if not view.empty():
                for addr, new in view.patches():
                    off = addr - view.base
                    patches.append((addr, new, bytes(view.orig[off:off + len(new)])))
                view_snap = (view.base, bytes(view.data), bytes(view.orig))
        except Exception as exc:
            app._fail(exc)
            return
        if not rip and not patches and not app.state.buffers:
            messagebox.showerror("Cheats", "Set up a call (RIP), buffers or hex edits in the other tabs first")
            return
        root = app.root

        def work() -> None:
            snap = collect(app, pid, rip, args, patches)
            snap.view = view_snap
            root.after(0, lambda: RecordDialog(self, snap))

        app._run_bg(work, "Capturing Caller state...")

    # ------------------------------------------------- JSON written for you
    def _editor_cheat(self) -> Optional[dict]:
        """The cheat in the editor as a dict (None when a game, not a cheat, is selected)."""
        if not self.cur or self.cur[1] is None:
            return None
        try:
            d = json.loads(self.editor.get("1.0", "end-1c"))
        except Exception as exc:
            messagebox.showerror("Cheats", f"The cheat text is not valid JSON, fix it first: {exc}")
            return None
        return d if isinstance(d, dict) else None

    def _put_cheat(self, d: dict, log: list[str]) -> None:
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", json.dumps(d, indent=2))
        self.on_save()
        if log:
            self.app.log_line("cheat editor: " + "; ".join(log))

    def _need_cheat(self) -> Optional[dict]:
        if not self.cur or self.cur[1] is None:
            messagebox.showerror("Cheats", "Select a cheat in the list first (or press New cheat).")
            return None
        return self._editor_cheat()

    def on_insert_call(self) -> None:
        """Adds the Caller tab's call to the selected cheat, plus an alloc (with the
        buffer's current contents) / code step for every @buffer it uses - also the
        ones only referenced inside quick-code assembly - and inputs for 'edit' regs."""
        d = self._need_cheat()
        if d is None:
            return
        app = self.app
        try:
            pid = app._pid()
        except Exception:
            pid = 0
        have = {str(x.get("name")) for x in d.get("steps", []) if isinstance(x, dict)
                and str(x.get("op", "")).lower() == "alloc"}

        def read(addr: int, n: int) -> bytes:
            return app.client.read(pid, addr, n) if pid and app.client.connected else b""

        def work() -> None:
            steps, params, notes = cheat_tools.caller_to_steps(app, read, have, d.get("params", []))

            def ui() -> None:
                if params:
                    d.setdefault("params", []).extend(params)
                log = cheat_tools.add_steps(d, steps)
                self._put_cheat(d, log + [f"{len(params)} input(s)"] if params else log)
                if notes:
                    messagebox.showwarning("Cheats", "\n".join(notes))
            app.root.after(0, ui)

        app._run_bg(work, "Reading buffers for the cheat...")

    def insert_step(self, step: dict) -> bool:
        """Add a step to the open cheat (used by the code cave dialog)."""
        d = self._need_cheat()
        if d is None:
            return False
        self._put_cheat(d, cheat_tools.add_steps(d, [step]))
        return True

    def send_steps(self, steps: list, params: list = (), suggested_name: str = "New cheat",
                   switch: bool = True) -> bool:
        """Add step(s) from elsewhere (disassembler, scanner...) to a cheat.  If a cheat is open it
        offers to add to it or make a new one; otherwise it makes a new cheat in the selected game."""
        if switch and hasattr(self.app, "notebook") and hasattr(self.app, "_cheats_editor_tab"):
            self.app.notebook.select(self.app._cheats_editor_tab)
        sel = self.cur or self._selection()
        game = sel[0] if sel else None
        if game is None:
            messagebox.showerror("Cheats", "Select the game (or a cheat) in the Cheat Editor to add this to, "
                                 "or press New game first.")
            return False
        open_ci = self.cur[1] if (self.cur and self.cur[0] is game) else None
        if open_ci is not None and 0 <= open_ci < len(game.cheats):
            ans = messagebox.askyesnocancel(
                "Send to Cheat Editor",
                f"Add {len(steps)} step(s) to the open cheat '{game.cheats[open_ci].name}'?\n\n"
                "Yes = add to it      No = make a new cheat")
            if ans is None:
                return False
            if ans:
                return self.insert_steps(steps, params)
        base = suggested_name.strip() or "New cheat"
        name, n = base, 1
        while any(x.name == name for x in game.cheats):
            n += 1
            name = f"{base} {n}"
        try:
            c = Cheat.from_dict({"name": name, "mode": "toggle",
                                 "author": self.app.author() if hasattr(self.app, "author") else "",
                                 "params": list(params), "steps": list(steps)})
        except Exception as exc:
            messagebox.showerror("Cheats", f"Could not make the cheat: {exc}")
            return False
        game.cheats.append(c)
        try:
            game.save()
        except Exception as exc:
            messagebox.showerror("Cheats", f"Not saved: {exc}")
            return False
        self.reload()
        self._fill(select=self.store.key(game, c))
        self.app.log_line(f"cheat editor: new cheat '{name}' ({len(steps)} step(s)) in {game.name}")
        return True

    def insert_steps(self, steps: list, params: list = ()) -> bool:
        """Add several steps (and the inputs they use) to the open cheat in one edit."""
        d = self._need_cheat()
        if d is None:
            return False
        have = {p.get("name") for p in d.get("params", []) if isinstance(p, dict)}
        new = [p for p in params if p.get("name") not in have]
        if new:
            d.setdefault("params", []).extend(new)
        log = cheat_tools.add_steps(d, list(steps))
        if new:
            log.append("added input(s) " + ", ".join("$" + p["name"] for p in new))
        self._put_cheat(d, log)
        return True

    def on_check_fix(self) -> None:
        """Find @buffers used before a step creates them and add the missing alloc /
        code steps from this session's buffers (with their current contents)."""
        d = self._need_cheat()
        if d is None:
            return
        missing = cheat_tools.check_cheat(d.get("steps", [])) + [
            n for n in cheat_tools.check_cheat(d.get("off", [])) if n not in cheat_tools.check_cheat(d.get("steps", []))]
        problems: list[str] = []
        for p in d.get("params", []):
            lst = p.get("items")
            if lst and not self.app.items.items(lst):
                problems.append(f"input '{p.get('name')}' uses item list '{lst}', which is not loaded")
        if not missing:
            messagebox.showinfo("Check & fix", "\n".join(problems) or "No problems found.")
            return
        app = self.app
        try:
            pid = app._pid()
        except Exception:
            pid = 0

        def read(addr: int, n: int) -> bytes:
            return app.client.read(pid, addr, n) if pid and app.client.connected else b""

        def work() -> None:
            steps, unknown, sets = cheat_tools.dependency_steps(app, set(missing), read, set())
            steps = [x for x in steps if x.get("name") in missing or x["op"] == "alloc"]

            def ui() -> None:
                log = cheat_tools.add_steps(d, steps, front=True) if steps else []
                if steps:
                    self._put_cheat(d, log)
                msg = []
                if steps:
                    msg.append("Added at the start of the cheat:\n  " + "\n  ".join(log))
                if unknown:
                    msg.append("Not fixable automatically (no such buffer in this session):\n  " +
                               ", ".join("@" + n for n in unknown) +
                               "\nCreate it in the Caller tab (Alloc + Write to buffer), then press Check & fix again.")
                messagebox.showinfo("Check & fix", "\n\n".join(msg + problems))
            app.root.after(0, ui)

        app._run_bg(work, "Checking cheat...")

    # ------------------------------------------------------- export / import
    def _export_selection(self) -> list:
        sel = self._selection()
        if not sel:
            return []
        g, ci = sel
        return [(g, list(g.cheats) if ci is None else [g.cheats[ci]])]

    def on_export(self) -> None:
        what = self._export_selection()
        if not what:
            messagebox.showerror("Cheats", "Select a game (exports all its cheats) or a single cheat")
            return
        from cheat_export_dialog import ExportDialog   # noqa: PLC0415
        g, cheats = what[0]
        ExportDialog(self.app, self.store, g, cheats)

    def on_copy_code(self) -> None:
        what = self._export_selection()
        if not what:
            messagebox.showerror("Cheats", "Select a game or a cheat first")
            return
        code = cheat_pack.to_code(cheat_pack.build_pack(what, self.app.items))
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(code)
        self.app.log_line(f"share code copied to the clipboard ({len(code)} characters)")

    def _import_pack(self, pack: dict, source: str, notes: Optional[list] = None, from_file: bool = False) -> None:
        import cheats as cheats_mod   # noqa: PLC0415
        py = [f"{g.get('name', '?')} › {c.get('name', '?')}" for g in pack.get("games", [])
              for c in g.get("cheats", []) if isinstance(c, dict)
              and (cheats_mod.has_python(c.get("steps", [])) or cheats_mod.has_python(c.get("off", [])))]
        if py and not messagebox.askyesno(
                "Import - Python code", f"{len(py)} cheat(s) in {source} contain Python steps:\n\n"
                + "\n".join(py[:10]) + ("\n…" if len(py) > 10 else "") +
                "\n\nPython steps can run ANY code on this PC when you turn the cheat on.  Only import them "
                "if you trust whoever made this file.\n\nImport anyway?", icon="warning"):
            self.app.log_line(f"import of {source} cancelled (contains Python steps)")
            return
        log = cheat_pack.merge_into(pack, self.games, self.folder, self.app.items,
                                    source=source if from_file else None) + list(notes or [])
        if pack.get("items"):
            self.app.items.reload()
            for cb in self.app.items.on_change:
                cb()
        self.reload()
        self.app.log_line(f"imported {source}: " + "; ".join(log))
        messagebox.showinfo("Import", "\n".join(log) or "Nothing new to import.")

    def on_paste_code(self) -> None:
        win = tk.Toplevel(self.app.root)
        win.title("Import share code")
        win.transient(self.app.root)
        f = ttk.Frame(win, padding=10)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Paste a share code (PS5C1:...) or cheat JSON:").pack(anchor="w")
        t = tk.Text(f, width=80, height=10, wrap="char", font=("Consolas", 9))
        t.pack(fill="both", expand=True, pady=6)
        try:
            clip = self.app.root.clipboard_get()
            if clip.strip().startswith(cheat_pack.CODE_PREFIX):
                t.insert("1.0", clip.strip())
        except tk.TclError:
            pass

        def ok() -> None:
            try:
                pack = cheat_pack.parse(t.get("1.0", "end-1c"))
            except Exception as exc:
                messagebox.showerror("Import", f"Could not read it: {exc}", parent=win)
                return
            win.destroy()
            self._import_pack(pack, "share code")

        ttk.Button(f, text="Import", style="Accent.TButton", command=ok).pack(anchor="e")

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
                    self.store.enabled.discard(self.store.key(game, old))
                game.cheats[ci] = new
                sel_key = self.store.key(game, new)
            game.save()
        except Exception as exc:
            messagebox.showerror("Cheats", f"Not saved: {exc}")
            return
        self._fill(select=sel_key)
        self.app.log_line(f"saved {game.path.name if game.path else game.name}")

    def _new_game_path(self, tid: str, ver: str, name: str) -> Path:
        """<TITLEID>_<VERSION>.json (the name GoldHEN / ShnExt cheat files use), _2, _3 ... if taken."""
        import game_ids  # noqa: PLC0415
        return game_ids.library_path(self.folder, tid, ver, name)

    def on_new_game(self) -> None:
        import game_ids  # noqa: PLC0415
        sel = self._selection()
        src: Optional[Game] = sel[0] if sel else None
        win = tk.Toplevel(self.app.root)
        win.title("New game")
        win.transient(self.app.root)
        win.resizable(False, False)
        f = ttk.Frame(win, padding=10)
        f.pack(fill="both", expand=True)
        name_v = tk.StringVar(value=src.name if src else "")
        tid_v = tk.StringVar(value=src.title_id if src else "")
        ver_v = tk.StringVar(value=src.version if src else "")
        cid_v = tk.StringVar(value=src.content_id if src else "")
        proc_v = tk.StringVar(value=(src.process if src else "") or "eboot.bin")
        copy_v = tk.BooleanVar(value=False)
        rows = (("Game name", name_v, 36), ("Title ID (CUSA#####, PPSA#####)", tid_v, 14),
                ("App version (01.03 / 01.000.000)", ver_v, 14), ("Content ID (optional)", cid_v, 40),
                ("Process", proc_v, 14))
        for r, (label, var, wd) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=2)
            ttk.Entry(f, textvariable=var, width=wd).grid(row=r, column=1, sticky="w", padx=(6, 0), pady=2)
        fetch = ttk.Button(f, text="From console")
        fetch.grid(row=1, column=1, sticky="e", padx=(6, 0))
        status = tk.StringVar(value="")
        ttk.Label(f, textvariable=status, foreground=theme.c("muted"), wraplength=420,
                  justify="left").grid(row=5, column=0, columnspan=2, sticky="w", pady=(4, 0))
        note = tk.StringVar()
        ttk.Label(f, textvariable=note, foreground=theme.c("muted"), wraplength=420,
                  justify="left").grid(row=6, column=0, columnspan=2, sticky="w", pady=(2, 2))
        if src:
            ttk.Checkbutton(f, text=f"Copy the {len(src.cheats)} cheat(s) of '{src.name}'",
                            variable=copy_v).grid(row=7, column=0, columnspan=2, sticky="w")

        def meta() -> dict:
            d, _fixed = game_ids.normalize({"game": name_v.get().strip(), "title_id": tid_v.get().strip(),
                                            "version": ver_v.get().strip(), "content_id": cid_v.get().strip(),
                                            "process": proc_v.get().strip()})
            return d

        def preview(*_a) -> None:
            d = meta()
            path = self._new_game_path(d["title_id"], d["version"], d["game"])
            msgs = [f"Saved as {path.name}"]
            if d["title_id"] and not game_ids.TITLE_ID_FULL.fullmatch(d["title_id"]):
                msgs.append("the title id must be CUSA##### or PPSA#####")
            if d["version"] and not game_ids.version_ok(d["version"], d["title_id"]):
                msgs.append(f"version {d['version']!r} is not an app version (01.03 on PS4, 01.000.000 on PS5)")
            elif not d["version"]:
                msgs.append("no version yet - cheat menus look for <TITLEID>_<VERSION> files")
            note.set("  -  ".join(msgs))
        for v in (name_v, tid_v, ver_v, cid_v):
            v.trace_add("write", preview)
        preview()

        def fill(run, err) -> None:
            if not win.winfo_exists():
                return
            if run is None:
                status.set(f"Could not read the game: {err}")
                return
            tid_v.set(run.title_id)
            ver_v.set(run.version)
            cid_v.set(run.content_id)
            proc_v.set(run.process or "eboot.bin")
            if not name_v.get().strip() or name_v.get().strip().upper() in (run.title_id, run.content_id):
                known = next((g.name for g in self.games if g.title_id == run.title_id), "")
                name_v.set(re.sub(r"\s*\((?:\d{4}-\d{2}-\d{2}|imported).*\)$", "", known) or run.title_id)
            status.set(f"From the console: {run.title_id}  v{run.version or '?'}  {run.content_id}"
                       + ("" if run.version else "  (no version reported - type it in)")
                       + ("" if name_v.get().strip() != run.title_id else "  - type the game's name"))

        fetch.configure(command=lambda: (status.set("Reading the game on the console..."),
                                         game_ids.ask_console(self.app, fill)))
        if not src and getattr(getattr(self.app, "client", None), "connected", False):
            fetch.invoke()                         # connected: fill the ids of the running game right away

        def ok() -> None:
            d = meta()
            name, tid = d["game"], d["title_id"]
            if not name_v.get().strip():
                messagebox.showerror("New game", "Enter a game name", parent=win)
                return
            path = self._new_game_path(tid, d["version"], name)
            base, k = name, 2
            while any(g.name == name for g in self.games):
                name, k = f"{base} ({k})", k + 1
            g = Game(name=name, title_id=tid, version=d["version"], path=path, content_id=d.get("content_id", ""),
                     author=self.app.author() if hasattr(self.app, "author") else "", process=d["process"])
            if src:
                g.author, g.notes = src.author or g.author, src.notes
            if src and copy_v.get():
                g.cheats = [Cheat.from_dict(c.to_dict()) for c in src.cheats]
            else:
                g.cheats.append(self._template())
            try:
                g.save()
            except Exception as exc:
                messagebox.showerror("New game", str(exc), parent=win)
                return
            win.destroy()
            self.app.log_line(f"new game file {path.name}")
            self.reload()
            self._select_game(path)

        b = ttk.Frame(f)
        b.grid(row=8, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(b, text="Create", style="Accent.TButton", command=ok).pack(side="left", padx=2)
        ttk.Button(b, text="Cancel", command=win.destroy).pack(side="left", padx=2)
        win.bind("<Return>", lambda e: ok())
        win.bind("<Escape>", lambda e: win.destroy())
        win.grab_set()

    def _select_game(self, path: Path) -> None:
        for iid, (g, ci) in self.iid_map.items():
            if ci is None and g.path == path:
                self.tree.selection_set(iid)
                self.tree.see(iid)
                return

    def on_delete_game(self) -> None:
        sel = self._selection()
        if not sel:
            messagebox.showerror("Cheats", "Select a game (or one of its cheats) first")
            return
        game = sel[0]
        if not game.path or not game.path.exists():
            self.reload()
            return
        on = [c.name for c in game.cheats if self.store.is_enabled(game, c)]
        msg = (f"Delete the game '{game.name}' [{game.title_id or '?'}] and its {len(game.cheats)} cheat(s)?\n\n"
               f"File: {game.path.name}\nIt is moved to the project's deleted\\ folder, so you can get it back.")
        if on:
            msg += ("\n\nStill ON in the game: " + ", ".join(on) +
                    "\nDeleting the file does not undo them - turn them off first if needed.")
        if not messagebox.askyesno("Delete game", msg, icon="warning"):
            return
        trash = self.folder / "deleted"
        trash.mkdir(exist_ok=True)
        dest = trash / f"{game.path.stem}_{datetime.datetime.now():%Y-%m-%d_%H%M%S}.json"
        try:
            shutil.move(str(game.path), str(dest))
        except Exception as exc:
            self.app._fail(exc)
            return
        for c in game.cheats:
            self.store.enabled.discard(self.store.key(game, c))
        self.cur = None
        self.app.log_line(f"deleted game {game.name} -> deleted\\{dest.name}")
        self.reload()

    # ------------------------------------------------------------ python steps
    def on_python_step(self) -> None:
        """Edit this cheat's {"op": "python"} step in the script window (adds one if there is none)."""
        d = self._need_cheat()
        if d is None:
            return
        game, _ci = self.cur
        steps = d.get("steps", [])
        idx = [i for i, st in enumerate(steps) if isinstance(st, dict) and str(st.get("op", "")).lower() == "python"]
        nth = 0
        if len(idx) > 1:
            n = simpledialog.askinteger("Python step", f"This cheat has {len(idx)} Python steps. "
                                        f"Edit which one (1-{len(idx)})?", minvalue=1, maxvalue=len(idx),
                                        parent=self.app.root)
            if not n:
                return
            nth = n - 1
        code = steps[idx[nth]].get("code", "") if idx else (
            "# This script runs as one step of the cheat (after the steps before it).\n"
            "# Patches made with ps5.patch(...) or write_..(undo=True) are restored when a toggle cheat is "
            "turned off.\n\n")
        holder = {"nth": nth if idx else None}
        gpath, cname = game.path, str(d.get("name", ""))

        def save(new_code: str) -> None:
            g = next((x for x in self.games if x.path == gpath), None)
            c = next((x for x in g.cheats if x.name == cname), None) if g else None
            if c is None:
                messagebox.showerror("Python step", f"The cheat '{cname}' is gone (renamed or deleted).")
                return
            py = [st for st in c.steps if isinstance(st, dict) and str(st.get("op", "")).lower() == "python"]
            if holder["nth"] is not None and holder["nth"] < len(py):
                py[holder["nth"]]["code"] = new_code
            else:
                c.steps.append({"op": "python", "code": new_code})
                holder["nth"] = len(py)
            g.save()
            if self.cur and self.cur[0] is g and self.cur[1] is not None and g.cheats[self.cur[1]].name == cname:
                self._fill(select=self.store.key(g, c))
                self._on_select()
            self.app.log_line(f"cheat editor: saved the Python step of '{cname}'")

        self.app.open_script_window_for(code, save, f"{game.name} › {cname} › Python step {nth + 1}")

    def add_python_cheat(self, name: str, code: str, mode: str = "once") -> Optional[str]:
        """New cheat (one python step) in the game selected here.  Returns an error text or None."""
        sel = self._selection()
        if not sel:
            return "Select a game in the Cheat Editor first."
        game = sel[0]
        if any(c.name == name for c in game.cheats):
            return f"'{game.name}' already has a cheat named '{name}'."
        c = Cheat.from_dict({"name": name, "mode": mode, "description": "Python script",
                             "steps": [{"op": "python", "code": code}]})
        game.cheats.append(c)
        game.save()
        self._fill(select=self.store.key(game, c))
        self.app.log_line(f"cheat editor: new cheat '{name}' in {game.name}")
        return None

    def _tree_menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.tree.focus(iid)
        sel = self._selection()
        m = tk.Menu(self.app.root, tearoff=0)
        if not sel:
            m.add_command(label="New game…", command=self.on_new_game)
            m.add_command(label="Reload", command=self.reload)
            m.tk_popup(event.x_root, event.y_root)
            return
        game, ci = sel
        if ci is None:                                   # a game row
            m.add_command(label="New cheat", command=self.on_new_cheat)
            m.add_command(label="New game…", command=self.on_new_game)
            m.add_separator()
            m.add_command(label="Export this game…", command=self.on_export)
            m.add_command(label="Copy as share code", command=self.on_copy_code)
            m.add_command(label="Show project folder", command=self.on_show_project)
            m.add_separator()
            m.add_command(label="Delete game…", command=self.on_delete_game)
        else:                                            # a cheat row
            c = game.cheats[ci]
            on = self.store.is_enabled(game, c)
            m.add_command(label="Disable" if on else "Enable (Run / Toggle)", command=self.on_run)
            m.add_separator()
            m.add_command(label="New cheat", command=self.on_new_cheat)
            m.add_command(label="Duplicate cheat", command=self._duplicate_cheat)
            m.add_command(label="Rename…", command=self._rename_cheat)
            has_hook = any(isinstance(s, dict) and str(s.get("op", "")).lower() == "hook" for s in c.steps)
            if has_hook:
                m.add_command(label="Edit code cave…", command=self._edit_cave_cheat)
            m.add_separator()
            m.add_command(label="Export this cheat…", command=self.on_export)
            m.add_command(label="Copy as share code", command=self.on_copy_code)
            m.add_separator()
            m.add_command(label="Delete cheat…", command=self.on_delete)
        m.tk_popup(event.x_root, event.y_root)

    def _duplicate_cheat(self) -> None:
        sel = self._selection()
        if not sel or sel[1] is None:
            return
        game, ci = sel
        d = game.cheats[ci].to_dict()
        base = d["name"] + " (copy)"
        name, n = base, 1
        while any(x.name == name for x in game.cheats):
            n += 1
            name = f"{base} {n}"
        d["name"] = name
        game.cheats.insert(ci + 1, Cheat.from_dict(d))
        game.save()
        self._fill(select=self.store.key(game, game.cheats[ci + 1]))
        self.app.log_line(f"duplicated cheat as '{name}'")

    def _rename_cheat(self) -> None:
        sel = self._selection()
        if not sel or sel[1] is None:
            return
        game, c = sel[0], sel[0].cheats[sel[1]]
        new = simpledialog.askstring("Rename cheat", "New name:", initialvalue=c.name, parent=self.app.root)
        if not new or new.strip() == c.name:
            return
        new = new.strip()
        if any(x.name == new for x in game.cheats):
            messagebox.showerror("Rename", f"'{new}' already exists in this game.")
            return
        was_on = self.store.is_enabled(game, c)
        self.store.enabled.discard(self.store.key(game, c))
        c.name = new
        game.save()
        if was_on:
            self.store.enabled.add(self.store.key(game, c))
        self._fill(select=self.store.key(game, c))
        self.app.log_line(f"renamed cheat to '{new}'")

    def _edit_cave_cheat(self) -> None:
        """Re-open a saved hook cheat's cave in the code-cave editor (edit its code / where it goes)."""
        sel = self._selection()
        if not sel or sel[1] is None:
            return
        game, c = sel[0], sel[0].cheats[sel[1]]
        hook = next((s for s in c.steps if isinstance(s, dict) and str(s.get("op", "")).lower() == "hook"), None)
        if hook is None:
            return
        messagebox.showinfo("Edit code cave",
                            "This cheat hooks at:\n  " + str(hook.get("addr")) +
                            "\n\nTo change the cave code, edit the \"asm\" of its hook step in the JSON on the "
                            "right, then press Save edits.  To re-record it live, open the address in the "
                            "Disassembler and choose Code cave.  (Where a cave lands in the executable on export "
                            "is chosen in the Export window's Code caves box.)")

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
        self._fill(select=self.store.key(game, c))

    def _template(self) -> Cheat:
        return Cheat(
            name="New cheat", description="", mode="toggle",
            author=self.app.author() if hasattr(self.app, "author") else "",
            steps=[{"op": "patch", "addr": "module(eboot.bin)+0x0", "type": "hex", "value": "90 90"}],
        )

    def on_delete(self) -> None:
        sel = self._selection()

        if sel and sel[1] is None:
            self.on_delete_game()
            return
        if not sel:
            messagebox.showerror("Cheats", "Select a cheat to delete")
            return

        game, ci = sel

        # Make sure the index is still valid
        if ci < 0 or ci >= len(game.cheats):
            self.reload()
            self.cur = None
            messagebox.showerror("Cheats", "The selected cheat is no longer valid.")
            return

        cheat = game.cheats[ci]

        if not messagebox.askyesno("Delete", f"Delete '{cheat.name}'?"):
            return

        del game.cheats[ci]

        game.save()

        self.cur = None
        self.reload()
    def on_import(self) -> None:
        """Any supported cheat file: this tool's .json / .ps5c, GoldHEN .json, .shn, .mc4,
        decrypted ShnExt (*.ProjReap / *.ReapPatch)."""
        paths = filedialog.askopenfilenames(
            title="Import cheats",
            filetypes=[("All cheat formats", " ".join(cheat_formats.EXTENSIONS)),
                       ("Compact cheat pack", "*.ps5c"), ("JSON (this tool / GoldHEN)", "*.json"),
                       ("SHN trainer", "*.shn"), ("MC4 (encrypted SHN)", "*.mc4"),
                       ("Decrypted ShnExt project", "*.ProjReap *.ReapPatch"), ("All", "*.*")])
        self._import_paths([Path(p) for p in paths])

    def on_import_folder(self) -> None:
        """A decrypted ShnExt project folder (the one with Patches/*.ReapPatch)."""
        d = filedialog.askdirectory(title="Decrypted ShnExt project folder")
        if d:
            self._import_paths([Path(d)])

    def _import_paths(self, paths: list) -> None:
        seen_projects: set = set()
        for p in paths:
            if p.suffix.lower() == ".reappatch":          # several patches of one project -> import it once
                proj = p.parent.parent if p.parent.name.lower() == "patches" else p.parent
                if any(proj.glob("*.ProjReap")):
                    if proj in seen_projects:
                        continue
                    seen_projects.add(proj)
                    p = proj
            try:
                pack, notes = cheat_formats.load_any(p)
            except Exception as exc:
                messagebox.showerror("Import", f"{p.name}: {exc}")
                continue
            self._import_pack(pack, p.name, notes, from_file=True)

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
        self.auto_frame = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="auto stack frame", variable=self.auto_frame,
                        command=self.on_preview).pack(side="left")

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
            frame = 0
            if self.auto_frame.get():
                resolved, frame = asmgen.auto_frame(resolved)
            resolved = asmgen.ensure_ret(resolved, self.auto_ret.get())
            raw = asmgen.assemble(resolved)
            size = self.size_var.get().strip()
            data = asmgen.pad(raw, int(size, 0) if size else None)
            note = (f"   auto stack frame: sub rsp, 0x{frame:X} / add rsp, 0x{frame:X} before ret" if frame else "")
            self._write_out(f"{len(raw)} bytes (padded to {len(data)}){note}\n\n" + data.hex(" "))
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
        if not self.auto_frame.get():
            step["auto_frame"] = False
        if self.tab.insert_step(step):
            self.win.destroy()