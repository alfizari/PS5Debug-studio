"""Export dialog: pick the file type, see which cheats fit it, export only those.

This tool's own formats (.ps5c pack, cheat JSON) keep everything.  The formats other cheat menus
load (.shn, .mc4, GoldHEN .json) can only hold fixed byte patches of the game executable, so
each cheat is checked first (cheat_export.analyze) and the ones that cannot be written are listed
with the reason - never written half-converted.
"""

from __future__ import annotations

import copy
import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from scrollable import fit_geometry

import cheat_export as ce
import cheat_pack
import cave_map
import game_ids

OWN = {
    "ps5c": ("Cheat pack for this tool (.ps5c) - keeps everything", ".ps5c"),
    "pack_json": ("Cheat JSON for this tool (.json) - keeps everything", ".json"),
}
ORDER = ("ps5c", "pack_json", "shn", "mc4", "json", "shnext")


def padding_runs(chunks, min_len: int = 64):
    """(start, length, byte) of every run of 00 or CC bytes at least min_len long; chunks yields
    (address, bytes) in order, runs may cross chunk borders."""
    import re as _re
    cur = None                                         # [start, length, byte]
    for addr, data in chunks:
        for mt in _re.finditer(rb"\x00+|\xcc+", data):
            st, ln, by = addr + mt.start(), mt.end() - mt.start(), data[mt.start()]
            if cur and cur[2] == by and cur[0] + cur[1] == st:
                cur[1] += ln                           # continues across the chunk border
            else:
                if cur and cur[1] >= min_len:
                    yield tuple(cur)
                cur = [st, ln, by]
            if mt.end() != len(data):                  # the run ends inside this chunk
                if cur[1] >= min_len:
                    yield tuple(cur)
                cur = None
        if data and cur and cur[0] + cur[1] != addr + len(data):
            if cur[1] >= min_len:
                yield tuple(cur)
            cur = None
    if cur and cur[1] >= min_len:
        yield tuple(cur)


class ExportDialog:
    def __init__(self, app, store, game, cheats: list) -> None:
        self.app, self.store, self.game = app, store, game
        self.cheats = list(cheats)
        self.reports: list = []
        self._orig: dict = {}                       # (address expression, size) -> original bytes read

        self.win = w = tk.Toplevel(app.root)
        w.title(f"Export cheats - {game.name}")
        w.transient(app.root)
        fit_geometry(w, 980, 600)
        w.minsize(760, 420)
        top = ttk.Frame(w, padding=10)
        top.pack(fill="both", expand=True)

        # ---- format
        ff = ttk.LabelFrame(top, text="File type", padding=6)
        ff.pack(fill="x")
        self.fmt = tk.StringVar(value=getattr(app, "_last_export_fmt", "ps5c"))
        sx_mod, sx_why = ce.shnext_module()
        if self.fmt.get() == "shnext" and sx_mod is None:
            self.fmt.set("ps5c")
        for k in ORDER:
            label = OWN[k][0] if k in OWN else ce.FORMATS[k][0] + {
                "shn": " - GoldHEN / etaHEN cheat menus (on/off patches)",
                "mc4": " - same as .shn, encrypted",
                "json": " - GoldHEN / etaHEN cheat menus (on/off + buttons)",
                "shnext": " - onionHEN / ShnExt (on/off patches of the executable)"}[k]
            if k == "shnext" and sx_mod is None:
                label += f"   [not available: {sx_why}]"
            ttk.Radiobutton(ff, text=label, value=k, variable=self.fmt, command=self._changed,
                            state="disabled" if (k == "shnext" and sx_mod is None) else "normal").pack(anchor="w")

        # ---- header: written into the file in the standard spelling (game_ids)
        self.hf = hf = ttk.LabelFrame(top, text="Written into the file", padding=6)
        self.hv = {}
        for i, (key, label, val, wd) in enumerate((
                ("name", "Game", game.name, 30), ("title_id", "Title id", game.title_id, 12),
                ("version", "Version", game.version, 12), ("author", "Author (Moder)", game.author or (app.author() if hasattr(app, "author") else ""), 18),
                ("process", "Process", game.process or "eboot.bin", 12))):
            row, col = divmod(i, 3)
            ttk.Label(hf, text=label).grid(row=row, column=2 * col, sticky="w", padx=(0 if col == 0 else 12, 4), pady=2)
            v = tk.StringVar(value=val or "")
            v.trace_add("write", lambda *_: self._refresh())
            ttk.Entry(hf, textvariable=v, width=wd).grid(row=row, column=2 * col + 1, sticky="w", pady=2)
            self.hv[key] = v
        self.cid = game.content_id
        self.fetch_btn = ttk.Button(hf, text="From console", command=self._from_console)
        self.fetch_btn.grid(row=1, column=4, columnspan=2, sticky="e", pady=2)
        self.head_msg = ttk.Label(hf, text="", foreground="#c0392b", wraplength=900, justify="left")
        self.head_msg.grid(row=2, column=0, columnspan=6, sticky="w", pady=(4, 0))

        # ---- cheats (tick which ones to export)
        self.lf = lf = ttk.LabelFrame(top, text="Cheats - tick the ones to export", padding=6)
        self.picked = set(range(len(self.cheats)))          # cheat indexes to export (all, by default)
        pickrow = ttk.Frame(lf)
        pickrow.pack(fill="x")
        ttk.Button(pickrow, text="All", style="Small.TButton", width=6,
                   command=lambda: self._pick_set(range(len(self.cheats)))).pack(side="left")
        ttk.Button(pickrow, text="None", style="Small.TButton", width=6,
                   command=lambda: self._pick_set(())).pack(side="left", padx=(4, 0))
        ttk.Button(pickrow, text="Only exportable", style="Small.TButton",
                   command=self._pick_exportable).pack(side="left", padx=(4, 0))
        ttk.Label(pickrow, text="Click the box, or Space to toggle", style="Muted.TLabel").pack(side="left", padx=(10, 0))
        tw = ttk.Frame(lf)
        tw.pack(fill="both", expand=True, pady=(4, 0))
        self.tree = ttk.Treeview(tw, columns=("pick", "st", "name", "lines", "why"), show="headings", height=10)
        for col, title, wd, st in (("pick", "", 30, False), ("st", "", 30, False), ("name", "Cheat", 220, False),
                                   ("lines", "Lines", 50, False), ("why", "Notes", 580, True)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=wd, stretch=st, anchor="center" if col in ("pick", "st", "lines") else "w")
        sb = ttk.Scrollbar(tw, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("bad", foreground="#c0392b")
        self.tree.tag_configure("need", foreground="#b9770e")
        self.tree.tag_configure("off", foreground="#9aa0a6")      # not ticked
        self.tree.bind("<Double-1>", self._show_detail)
        self.tree.bind("<Button-1>", self._tree_click, add="+")
        self.tree.bind("<space>", self._toggle_selected)

        # ---- original bytes
        self.of = of = ttk.Frame(top)
        self.read_btn = ttk.Button(of, text="Read original bytes from the game", command=self._read_originals)
        self.read_btn.pack(side="left")
        self.read_msg = ttk.Label(of, text="", wraplength=700, justify="left")
        self.read_msg.pack(side="left", padx=8)

        # ---- code caves (hooks / buffers) for .shn / .mc4 / GoldHEN .json
        self.cf = cf = ttk.LabelFrame(top, text="Code caves (cheats with a hook or @buffers)", padding=6)
        saved = getattr(app, "_cave_offsets", {}).get((game.title_id or "").upper(), {})
        self.cave_code = tk.StringVar(value=saved.get("code", ""))
        self.cave_data = tk.StringVar(value=saved.get("data", ""))
        self._cave_free: dict = {}
        ttk.Label(cf, text="Cave code at module(main)+0x").grid(row=0, column=0, sticky="w")
        ttk.Entry(cf, textvariable=self.cave_code, width=12).grid(row=0, column=1, sticky="w")
        ttk.Label(cf, text="  buffers the code writes at +0x").grid(row=0, column=2, sticky="w")
        ttk.Entry(cf, textvariable=self.cave_data, width=12).grid(row=0, column=3, sticky="w")
        self.find_btn = ttk.Button(cf, text="Find free space", command=self._find_cave)
        self.find_btn.grid(row=0, column=4, padx=(10, 0))
        self.cave_msg = ttk.Label(cf, text="", wraplength=900, justify="left")
        self.cave_msg.grid(row=1, column=0, columnspan=6, sticky="w", pady=(4, 0))
        ttk.Label(cf, foreground="#7f8c8d", wraplength=900, justify="left", text=(
            "These formats have no memory of their own, so the cave code is written into unused bytes of the "
            "game executable (00 / CC padding) and simply stays there; turning the cheat off restores the hook. "
            "Offsets are the module(main)+0x... numbers this tool shows - nothing to subtract (the .shn "
            "Offset is the same number). Buffers the code only reads go next to the code; buffers it writes "
            "need memory the game does not use (code pages are read-only).")).grid(
            row=2, column=0, columnspan=6, sticky="w", pady=(2, 0))
        resrow = ttk.Frame(cf)
        resrow.grid(row=3, column=0, columnspan=6, sticky="w", pady=(4, 0))
        self.reserved_var = tk.StringVar(value="")
        ttk.Label(resrow, textvariable=self.reserved_var, foreground="#7f8c8d").pack(side="left")
        ttk.Button(resrow, text="Manage used space…", style="Small.TButton",
                   command=self._manage_caves).pack(side="left", padx=(8, 0))
        self.record_caves = tk.BooleanVar(value=True)
        ttk.Checkbutton(resrow, text="Record the space used after export (avoids overlap next time)",
                        variable=self.record_caves).pack(side="left", padx=(12, 0))
        for v in (self.cave_code, self.cave_data):
            v.trace_add("write", lambda *_: self._cave_edited())
        self._refresh_reserved()

        # ---- buttons
        bf = ttk.Frame(top)
        bf.pack(side="bottom", fill="x", pady=(8, 0))
        self.summary = ttk.Label(bf, text="")
        self.summary.pack(side="left")
        ttk.Button(bf, text="Cancel", command=w.destroy).pack(side="right")
        self.go = ttk.Button(bf, text="Export...", style="Accent.TButton", command=self._export)
        self.go.pack(side="right", padx=6)
        self._changed()

    # ------------------------------------------------------------------
    def _hdr_game(self):
        g = copy.copy(self.game)
        for k, v in self.hv.items():
            setattr(g, k, v.get().strip())
        d, _fixed = game_ids.normalize({"game": g.name, "title_id": g.title_id, "version": g.version,
                                        "process": g.process, "content_id": self.cid})
        g.name, g.title_id, g.version, g.process = d["game"], d["title_id"].upper(), d["version"], d["process"]
        g.content_id = d.get("content_id", "")
        return g

    def _from_console(self) -> None:
        """Title id / version / process of the game running now, read like Reaper Studio does."""
        self.head_msg.configure(text="Reading the game on the console...", foreground="#7f8c8d")

        def done(run, err) -> None:
            if not self.win.winfo_exists():
                return
            if run is None:
                self.head_msg.configure(text=f"✖ could not read the game: {err}", foreground="#c0392b")
                return
            if self.hv["title_id"].get().strip() and self.hv["title_id"].get().strip().upper() != run.title_id:
                if not messagebox.askyesno(
                        "From console", f"The console is running {run.title_id}, but these cheats are for "
                        f"{self.hv['title_id'].get().strip().upper()}.\n\nUse {run.title_id} anyway?", parent=self.win):
                    self._refresh()
                    return
            self.cid = run.content_id
            self.hv["title_id"].set(run.title_id)
            if run.version:
                self.hv["version"].set(run.version)
            self.hv["process"].set(run.process or "eboot.bin")
            g = self.game                     # remember them in the game entry too (same title only)
            if g.title_id.upper() in ("", run.title_id) and g.path is not None and (
                    g.title_id != run.title_id or (run.version and g.version != run.version)
                    or (run.content_id and g.content_id != run.content_id)):
                g.title_id, g.content_id = run.title_id, run.content_id or g.content_id
                g.version = run.version or g.version
                g.process = g.process or run.process or "eboot.bin"
                try:
                    g.save()
                    self.app.log_line(f"{g.name}: title id / version from the console saved ({g.title_id} v{g.version})")
                except Exception as exc:
                    self.app.log_line(f"{g.name}: could not save the ids ({exc})")
            self._changed()
            if not run.version:
                self.head_msg.configure(text=self.head_msg.cget("text") + "\n⚠ the console did not report a "
                                        "version (older payload?) - type it in", foreground="#b9770e")
        game_ids.ask_console(self.app, done)

    def _items(self) -> dict:
        """item ID lists the cheats use (ShnExt writes them as dropdown dictionaries)"""
        store = getattr(self.app, "items", None)
        lists = {p.get("items") for c in self.cheats for p in c.params if isinstance(p, dict) and p.get("items")}
        return {x: store.items(x) for x in lists if store is not None and store.items(x)}

    def _changed(self) -> None:
        fmt = self.fmt.get()
        self.app._last_export_fmt = fmt
        own = fmt in OWN
        for f in (self.hf, self.lf, self.of, self.cf):
            f.pack_forget()
        self.hf.pack(fill="x", pady=(8, 0))             # every format: the same naming standard
        caves = fmt in ("shn", "mc4", "json") and self._has_caves()
        if not own:
            self.of.pack(side="bottom", fill="x", pady=(6, 0))
            if caves:
                self.cf.pack(side="bottom", fill="x", pady=(6, 0))
        self.lf.pack(fill="both", expand=True, pady=(8, 0))   # tick-which-to-export: shown for every format
        plan = self._cave_plan() if caves else None
        hg = self._hdr_game()
        self.reports = [] if own else [ce.analyze(hg, c, fmt, self._items(), cave=plan) for c in self.cheats]
        self._plan = plan
        for r in self.reports:                           # original bytes already read for another type
            for ln in r.missing_off():
                ln.off = self._orig.get((ln.addr, len(ln.on)))
        self._refresh()

    def _show_head(self, errs: list, warns: list) -> None:
        hg = self._hdr_game()
        fixed = [f"{k} {getattr(hg, a)!r}" for k, a in (("version", "version"), ("title id", "title_id"))
                 if self.hv[a].get().strip() and getattr(hg, a) != self.hv[a].get().strip()]
        info = (["✔ written as " + ", ".join(fixed)] if fixed else [])
        self.head_msg.configure(text="\n".join(["✖ " + e for e in errs] + ["⚠ " + x for x in warns] + info),
                                foreground="#c0392b" if errs else "#b9770e")

    def _refresh(self) -> None:
        fmt = self.fmt.get()
        self.tree.delete(*self.tree.get_children())
        if fmt in OWN:
            lists = sorted({p.get("items") for c in self.cheats for p in c.params if p.get("items")})
            have = [x for x in lists if self.app.items is not None and self.app.items.items(x)]
            missing = [x for x in lists if x not in have]
            for i, c in enumerate(self.cheats):
                picked = i in self.picked
                self.tree.insert("", "end", iid=str(i), tags=() if picked else ("off",),
                                 values=(self._box(picked), "✔", c.name, "", "keeps every step"))
            errs, warns = ce.check_game(self._hdr_game(), fmt)
            self._show_head(errs, warns)
            n = len(self.picked)
            txt = f"{n} of {len(self.cheats)} cheat(s) ticked - this tool's own format keeps every step"
            if have:
                txt += f" \u00b7 item ID list(s): {', '.join(have)}"
            if missing:
                txt += f" \u00b7 \u26a0 item list(s) not found: {', '.join(missing)}"
            self.summary.configure(text=txt)
            self.go.configure(text=f"Export {n} cheat(s)...", state="disabled" if (errs or not n) else "normal")
            return
        errs, warns = ce.check_game(self._hdr_game(), fmt)
        self._show_head(errs, warns)
        need = 0
        for i, r in enumerate(self.reports):
            if r.errors:
                st, tag, why = "✖", "bad", r.errors[0] + (f"  (+{len(r.errors) - 1} more)" if len(r.errors) > 1 else "")
            elif r.missing_off():
                need += 1
                st, tag = "?", "need"
                why = (f"needs the original bytes for {len(r.missing_off())} line(s) (the off value) - "
                       "press 'Read original bytes from the game', or add off steps")
            else:
                st, tag, why = "✔", "", "; ".join(r.warnings) or "ok"
            if getattr(r, "summary", ""):
                why = f"{why}  -  {r.summary}" if why != "ok" else f"ok  -  {r.summary}"
            picked = i in self.picked
            self.tree.insert("", "end", iid=str(i),
                             values=(self._box(picked), st, r.cheat.name, len(r.lines) or "", why),
                             tags=(tag,) if picked else ("off",))
        ok = sum(1 for i, r in enumerate(self.reports) if r.ok and i in self.picked)
        skip_bad = sum(1 for i, r in enumerate(self.reports) if r.errors and i in self.picked)
        need_pick = sum(1 for i, r in enumerate(self.reports) if r.missing_off() and i in self.picked)
        parts = [f"{ok} ticked cheat(s) ready to export"]
        if need_pick:
            parts.append(f"{need_pick} ticked need original bytes")
        if skip_bad:
            parts.append(f"{skip_bad} ticked cannot be written as {ce.FORMATS[fmt][1]} (double-click for why)")
        self.summary.configure(text=" · ".join(parts))
        self.go.configure(text=f"Export {ok} cheat(s)...", state="normal" if ok and not errs else "disabled")
        connected = bool(getattr(self.app.client, "connected", False))
        self.read_btn.configure(state="normal" if need and connected else "disabled")
        if need and not connected:
            self.read_msg.configure(text="Connect to the console with the game running to read them.")

    # ------------------------------------------------------------------ code caves
    def _has_caves(self) -> bool:
        return any(str(s.get("op", "")).lower() in ("hook", "alloc") for c in self.cheats for s in c.steps
                   if isinstance(s, dict))

    @staticmethod
    def _hex(text: str):
        t = text.strip().lower().replace("module(main)+", "")
        if not t:
            return None
        try:
            return int(t, 16)
        except ValueError:
            return None

    def _cave_plan(self) -> "ce.CavePlan":
        code, data = self._hex(self.cave_code.get()), self._hex(self.cave_data.get())
        free = self._cave_free.get(code)
        return ce.CavePlan(code_off=code, data_off=data, code_free=free)

    def _cave_edited(self) -> None:
        store = getattr(self.app, "_cave_offsets", None)
        if store is None:
            store = self.app._cave_offsets = {}
        store[(self.game.title_id or "").upper()] = {"code": self.cave_code.get().strip(),
                                                    "data": self.cave_data.get().strip()}
        bad = [n for n, v in (("cave code", self.cave_code), ("data", self.cave_data))
               if v.get().strip() and self._hex(v.get()) is None]
        self.cave_msg.configure(text=("✖ " + ", ".join(bad) + ": write a hex offset like 1BC000") if bad else "",
                                foreground="#c0392b")
        if self._job_cave:
            self.win.after_cancel(self._job_cave)
        self._job_cave = self.win.after(300, self._changed)

    _job_cave = None

    # --------------------------------------------- record of cave space used (cave_map)
    def _reserved(self):
        g = self._hdr_game()
        return cave_map.regions(self.store.folder, g.title_id, g.version)

    def _refresh_reserved(self) -> None:
        n = len(self._reserved())
        self.reserved_var.set(f"{n} region(s) already used by earlier exports" if n
                              else "no cave space recorded yet for this game")

    def _manage_caves(self) -> None:
        g = self._hdr_game()
        rows = self._reserved()
        win = tk.Toplevel(self.win)
        win.title(f"Code cave space used - {g.title_id} v{g.version}")
        fit_geometry(win, 560, 320)
        ttk.Label(win, padding=8, wraplength=540, justify="left", text=(
            "Regions of the game executable earlier exports placed caves in. 'Find free space' avoids these. "
            "Remove one to let the space be reused.")).pack(fill="x")
        tv = ttk.Treeview(win, columns=("off", "len", "label"), show="headings", height=9)
        for c, t, w in (("off", "module(main)+0x", 140), ("len", "Bytes", 70), ("label", "From", 320)):
            tv.heading(c, text=t)
            tv.column(c, width=w, anchor="w")
        tv.pack(fill="both", expand=True, padx=8)
        def fill():
            tv.delete(*tv.get_children())
            for off, ln, lbl in cave_map.regions(self.store.folder, g.title_id, g.version):
                tv.insert("", "end", iid=str(off), values=(f"{off:X}", ln, lbl))
        fill()
        bar = ttk.Frame(win, padding=8)
        bar.pack(fill="x")
        def rm():
            for iid in tv.selection():
                cave_map.remove(self.store.folder, g.title_id, g.version, int(iid))
            fill(); self._refresh_reserved(); self._changed()
        def clear_all():
            if messagebox.askyesno("Clear", "Forget all recorded cave space for this game?", parent=win):
                cave_map.clear(self.store.folder, g.title_id, g.version)
                fill(); self._refresh_reserved(); self._changed()
        ttk.Button(bar, text="Remove selected", command=rm).pack(side="left")
        ttk.Button(bar, text="Clear all", command=clear_all).pack(side="left", padx=6)
        ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")

    def _reserve_used(self, fname: str) -> None:
        """After an export, remember the executable space the caves took, so the next export avoids it."""
        plan = getattr(self, "_plan", None)
        if not (plan and getattr(self, "record_caves", None) and self.record_caves.get()):
            return
        g = self._hdr_game()
        picked_names = [self.reports[i].cheat.name for i in sorted(self.picked)
                        if i < len(self.reports) and self.reports[i].ok]
        label = f"{', '.join(picked_names[:2])}{'...' if len(picked_names) > 2 else ''} ({fname})"
        if plan.code_off is not None and plan.used_code:
            cave_map.reserve(self.store.folder, g.title_id, g.version, plan.code_off, plan.used_code, label)
        if plan.data_off is not None and plan.used_data:
            cave_map.reserve(self.store.folder, g.title_id, g.version, plan.data_off, plan.used_data, label + " [data]")
        self._refresh_reserved()

    def _cave_need(self) -> int:
        """bytes the caves of the selected cheats take (assembled at a trial offset)"""
        plan = ce.CavePlan(code_off=0, data_off=0x10000000)
        hg = self._hdr_game()
        for c in self.cheats:
            ce.analyze(hg, c, self.fmt.get(), self._items(), cave=plan)
        return max(plan.used_code, 16)

    def _find_cave(self) -> None:
        """Scan the game's executable code for 00 / CC padding big enough for the caves (or check the
        offset typed in).  Runs of padding at the END of a code mapping are preferred: that is space the
        linker left after the last function, never used by the game."""
        if not getattr(self.app.client, "connected", False):
            self.cave_msg.configure(text="Connect to the console with the game running first.", foreground="#b9770e")
            return
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.cave_msg.configure(text=str(exc), foreground="#c0392b")
            return
        need = self._cave_need()
        typed = self._hex(self.cave_code.get())
        app, client = self.app, self.app.client
        self.cave_msg.configure(text="Reading the game's code...", foreground="#7f8c8d")

        def post(fn):
            app.root.after(0, lambda: self.win.winfo_exists() and fn())

        reserved_off = self._reserved()                     # (off, len, label) from earlier exports

        def work() -> None:
            maps = client.maps(pid)
            exe = [m for m in maps if m.prot & 4]
            if not exe:
                raise RuntimeError("the game has no executable mapping")
            main = min(exe, key=lambda m: m.start)
            base = main.start
            reserved_abs = [(base + o, n, l) for o, n, l in reserved_off]
            code_maps = sorted((m for m in exe if m.name == main.name), key=lambda m: m.start)
            relocate = ""
            if typed is not None:
                at = base + typed
                m = next((m for m in code_maps if m.start <= at < m.end), None)
                if m is None:
                    post(lambda: self.cave_msg.configure(
                        text=f"✖ +0x{typed:X} is not in the game's code - searching for free space instead...",
                        foreground="#b9770e"))
                    relocate = f"+0x{typed:X} is not in the game's code"
                else:
                    n = min(need, m.end - at)
                    b = client.read(pid, at, n)
                    clash = next((l for ro, rn, l in reserved_abs if at < ro + rn and ro < at + need), None)
                    if n == need and all(x in (0x00, 0xCC) for x in b) and clash is None:
                        chunk = client.read(pid, at, min(m.end - at, 0x10000))
                        fb = chunk[0]
                        free = next((i for i, x in enumerate(chunk) if x != fb), len(chunk))
                        for ro, rn, _l in reserved_abs:                    # stop the count at a reserved region
                            if at < ro:
                                free = min(free, ro - at)
                        self._cave_free[typed] = free
                        pad = "CC" if b[:1] == b"\xcc" else "00"
                        post(lambda f=free, pd=pad: (self.cave_msg.configure(
                            text=f"✔ +0x{typed:X}: {f} free bytes ({pd} padding), the caves need {need}",
                            foreground="#1e8449"), self._changed()))
                        return
                    relocate = (f"+0x{typed:X} overlaps space used by '{clash}'" if clash
                                else f"+0x{typed:X} is not free")
                # the typed offset is not usable -> fall through and find a clear spot automatically
            best = None                               # (kind, length, start, byte)
            for m in code_maps:
                def chunks(m=m):
                    pos = m.start
                    while pos < m.end:
                        n = min(0x100000, m.end - pos)
                        try:
                            yield pos, client.read(pid, pos, n)
                        except Exception:
                            yield pos, b"\x01" * n       # unreadable: not free
                        pos += n
                        post(lambda p=pos: self.cave_msg.configure(
                            text=f"Reading the game's code... {100 * (p - m.start) // max(1, m.end - m.start)}% "
                                 f"of {m.name}", foreground="#7f8c8d"))
                for start, length, byte in padding_runs(chunks(), 64):
                    run_end = start + length
                    for fstart, flen in cave_map.subtract(start, length, reserved_abs):
                        if flen < 64:
                            continue
                        kind = 2 if fstart + flen == m.end else (1 if byte == 0xCC else 0)
                        if best is None or (flen >= need, kind, flen) > (best[1] >= need, best[0], best[1]):
                            best = (kind, flen, fstart, byte)
            if best is None:
                post(lambda: self.cave_msg.configure(text="✖ no free 00 / CC space of 64+ bytes in the game's code",
                                                     foreground="#c0392b"))
                return
            kind, length, start, byte = best
            off = ((start - base) + 15) & ~15
            free = start + length - (base + off)
            self._cave_free[off] = free

            def done():
                self.cave_code.set(f"{off:X}")
                what = {2: "at the end of the code", 1: "int3 (CC) padding", 0: "zero padding inside the code"}[kind]
                warn = "" if kind else "  ⚠ zeros inside the code can be data - prefer CC / end-of-code space"
                moved = f"{relocate} - moved to  " if relocate else ""
                ok = free >= need
                self.cave_msg.configure(
                    text=f"{'✔' if ok else '✖'} {moved}free space +0x{off:X}: {free} bytes ({what}), "
                         f"the caves need {need}{warn}",
                    foreground="#1e8449" if ok and kind else ("#b9770e" if ok else "#c0392b"))
            post(done)

        app._run_bg(work, "Looking for free space in the game's code...")

    # ------------------------------------------------------------- pick which cheats
    def _pick_set(self, idxs):
        self.picked = set(int(i) for i in idxs)
        self._refresh()

    def _pick_exportable(self):
        if self.fmt.get() in OWN:
            self.picked = set(range(len(self.cheats)))
        else:
            self.picked = {i for i, r in enumerate(self.reports) if r.ok}
        self._refresh()

    def _toggle(self, i):
        self.picked.discard(i) if i in self.picked else self.picked.add(i)
        self._refresh()

    def _tree_click(self, e):
        if self.tree.identify_region(e.x, e.y) != "cell" or self.tree.identify_column(e.x) != "#1":
            return
        iid = self.tree.identify_row(e.y)
        if iid != "":
            self._toggle(int(iid))
            return "break"

    def _toggle_selected(self, _e=None):
        for iid in self.tree.selection():
            self.picked.discard(int(iid)) if int(iid) in self.picked else self.picked.add(int(iid))
        self._refresh()
        return "break"

    @staticmethod
    def _box(on):
        return "☑" if on else "☐"

    def _show_detail(self, _e=None) -> None:
        sel = self.tree.selection()
        if not sel or self.fmt.get() in OWN:
            return
        r = self.reports[int(sel[0])]
        lines = [f"{ln.what}:  {'section ' + str(ln.section) + ' ' if ln.section else ''}offset {ln.offset:X}\n"
                 f"    on  {ln.on.hex(' ').upper()}\n    off {ln.off.hex(' ').upper() if ln.off is not None else '(not known yet)'}"
                 for ln in r.lines]
        parts = []
        if r.errors:
            parts.append("Problems:\n" + "\n".join("  \u2716 " + e for e in r.errors))
        if r.warnings:
            parts.append("Notes:\n" + "\n".join("  \u26a0 " + x for x in r.warnings))
        if lines:
            parts.append("\n".join(lines))
        text = "\n\n".join(parts)
        messagebox.showinfo(r.cheat.name, text or "ok", parent=self.win)

    # ------------------------------------------------------------------
    def _read_originals(self) -> None:
        app = self.app
        try:
            pid = app._pid()
        except Exception:
            messagebox.showerror("Export", "Set the game's process id first (top bar / Find process).", parent=self.win)
            return
        todo = [r for r in self.reports if not r.errors and r.missing_off()]
        on_now = [r.cheat.name for r in todo if self.store.is_enabled(self.game, r.cheat)]
        if on_now:
            messagebox.showerror("Export", "Turn these cheats off first - while they are on, the game has the "
                                 "patched bytes, not the originals:\n\n" + "\n".join(on_now), parent=self.win)
            return
        if not messagebox.askokcancel(
                "Read original bytes", f"Read the original bytes of {sum(len(r.missing_off()) for r in todo)} "
                f"line(s) from process {pid}?\n\nThe running game must be {self.game.name} "
                f"{self._hdr_game().version} - other versions have different code at these offsets.",
                parent=self.win):
            return
        import cheats as cheats_mod

        def work() -> None:
            rt = cheats_mod.Runtime(app.client, app.state, pid, app.make_cheat_buffer, lambda m: None, [])
            def read(expr: str, n: int) -> bytes:
                b = app.client.read(pid, rt.ev(expr), n)
                self._orig[(expr, n)] = b
                return b
            errs = ce.fill_originals(todo, read)

            def done() -> None:
                if not self.win.winfo_exists():
                    return
                n = sum(len(r.lines) for r in todo)
                self.read_msg.configure(text=(f"Read {n - len(errs)} line(s) from process {pid}."
                                              + (f"  {len(errs)} failed." if errs else "")))
                self._refresh()
            app.root.after(0, done)

        app._run_bg(work, "Reading original bytes...")

    def _exports_dir(self) -> str:
        d = Path(self.store.folder) / "exports"
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            return str(self.store.folder)
        return str(d)

    def _export(self) -> None:
        fmt = self.fmt.get()
        if fmt in OWN:
            g = self._hdr_game()
            if ce.check_game(g, fmt)[0]:
                return
            picked = [self.cheats[i] for i in sorted(self.picked)]
            if not picked:
                return
            ext = OWN[fmt][1]
            name = game_ids.file_stem(g.title_id, g.version, g.name) + (
                "" if len(picked) == len(self.game.cheats) else "_" + cheat_pack._slug(picked[0].name))
            path = filedialog.asksaveasfilename(parent=self.win, title="Export cheats", defaultextension=ext,
                                                initialdir=self._exports_dir(),
                                                initialfile=name + ext, filetypes=[(OWN[fmt][0], "*" + ext)])
            if not path:
                return
            pack = cheat_pack.build_pack([(g, picked)], self.app.items)
            if fmt == "pack_json":
                Path(path).write_text(json.dumps(pack, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                Path(path).write_bytes(cheat_pack.to_file_bytes(pack))
            self.app.log_line(f"exported {len(picked)} cheat(s) of {g.name} "
                              f"(+{len(pack['items'])} item list(s)) to {path}")
            self.win.destroy()
            return
        hg = self._hdr_game()
        errs, _w = ce.check_game(hg, fmt)
        ok = [r for i, r in enumerate(self.reports) if r.ok and i in self.picked]
        if errs or not ok:
            return
        skipped = [r.cheat.name for i, r in enumerate(self.reports) if i in self.picked and not r.ok]
        if skipped and not messagebox.askokcancel(
                "Export", f"{len(skipped)} cheat(s) are left out (they cannot be written as {ce.FORMATS[fmt][1]}):\n\n"
                + "\n".join(skipped[:15]) + ("\n..." if len(skipped) > 15 else "") +
                f"\n\nExport the other {len(ok)}?", parent=self.win):
            return
        ext = ce.FORMATS[fmt][1]
        path = filedialog.asksaveasfilename(parent=self.win, title=f"Export as {ext}", defaultextension=ext,
                                            initialdir=self._exports_dir(),
                                            initialfile=ce.default_name(hg, fmt),
                                            filetypes=[(ce.FORMATS[fmt][0], "*" + ext)])
        if not path:
            return
        if not path.lower().endswith(ext):
            path += ext                                  # never write mc4 bytes into a .shn etc.
        try:
            data = ce.build(fmt, hg, ok, self._items())
        except Exception as exc:
            messagebox.showerror("Export", f"Could not build the {ext} file:\n\n{exc}", parent=self.win)
            return
        Path(path).write_bytes(data)
        if getattr(self, "_plan", None) is not None and (self._plan.used_code or self._plan.used_data):
            self._reserve_used(Path(path).name)         # remember the executable space the caves took
        want = ce.default_name(hg, fmt)
        note = "" if Path(path).name == want else f"  (cheat menus expect the name {want})"
        self.app.log_line(f"exported {len(ok)} cheat(s) of {hg.name} as {ext} to {path}"
                          + (f", left out {len(skipped)}" if skipped else "") + note)
        self.win.destroy()
