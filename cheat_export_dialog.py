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

OWN = {
    "ps5c": ("Cheat pack for this tool (.ps5c) - keeps everything", ".ps5c"),
    "pack_json": ("Cheat JSON for this tool (.json) - keeps everything", ".json"),
}
ORDER = ("ps5c", "pack_json", "shn", "mc4", "json", "shnext")


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

        # ---- header (only used for the external formats; the game itself is not changed)
        self.hf = hf = ttk.LabelFrame(top, text="Written into the file (your game entry is not changed)", padding=6)
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
        self.head_msg = ttk.Label(hf, text="", foreground="#c0392b", wraplength=900, justify="left")
        self.head_msg.grid(row=2, column=0, columnspan=6, sticky="w", pady=(4, 0))

        # ---- cheats
        self.lf = lf = ttk.LabelFrame(top, text="Cheats", padding=6)
        self.tree = ttk.Treeview(lf, columns=("st", "name", "lines", "why"), show="headings", height=10)
        for col, title, wd, st in (("st", "", 34, False), ("name", "Cheat", 220, False),
                                   ("lines", "Lines", 50, False), ("why", "Notes", 600, True)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=wd, stretch=st, anchor="center" if col in ("st", "lines") else "w")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("bad", foreground="#c0392b")
        self.tree.tag_configure("need", foreground="#b9770e")
        self.tree.bind("<Double-1>", self._show_detail)

        # ---- original bytes
        self.of = of = ttk.Frame(top)
        self.read_btn = ttk.Button(of, text="Read original bytes from the game", command=self._read_originals)
        self.read_btn.pack(side="left")
        self.read_msg = ttk.Label(of, text="", wraplength=700, justify="left")
        self.read_msg.pack(side="left", padx=8)

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
        g.title_id = g.title_id.upper()
        return g

    def _items(self) -> dict:
        """item ID lists the cheats use (ShnExt writes them as dropdown dictionaries)"""
        store = getattr(self.app, "items", None)
        lists = {p.get("items") for c in self.cheats for p in c.params if isinstance(p, dict) and p.get("items")}
        return {x: store.items(x) for x in lists if store is not None and store.items(x)}

    def _changed(self) -> None:
        fmt = self.fmt.get()
        self.app._last_export_fmt = fmt
        own = fmt in OWN
        for f in (self.hf, self.lf, self.of):
            f.pack_forget()
        if not own:
            self.hf.pack(fill="x", pady=(8, 0))
            self.of.pack(side="bottom", fill="x", pady=(6, 0))
            self.lf.pack(fill="both", expand=True, pady=(8, 0))
        self.reports = [] if own else [ce.analyze(self._hdr_game(), c, fmt, self._items()) for c in self.cheats]
        for r in self.reports:                           # original bytes already read for another type
            for ln in r.missing_off():
                ln.off = self._orig.get((ln.addr, len(ln.on)))
        self._refresh()

    def _refresh(self) -> None:
        fmt = self.fmt.get()
        if fmt in OWN:
            lists = sorted({p.get("items") for c in self.cheats for p in c.params if p.get("items")})
            have = [x for x in lists if self.app.items is not None and self.app.items.items(x)]
            missing = [x for x in lists if x not in have]
            txt = f"{len(self.cheats)} cheat(s) - this tool's own format keeps every step"
            if have:
                txt += f" \u00b7 includes {len(have)} item ID list(s): {', '.join(have)}"
            if missing:
                txt += f" \u00b7 \u26a0 item list(s) not found in this project: {', '.join(missing)}"
            self.summary.configure(text=txt)
            self.go.configure(text=f"Export {len(self.cheats)} cheat(s)...", state="normal")
            return
        errs, warns = ce.check_game(self._hdr_game(), fmt)
        self.head_msg.configure(text="\n".join(["✖ " + e for e in errs] + ["⚠ " + x for x in warns]),
                                foreground="#c0392b" if errs else "#b9770e")
        self.tree.delete(*self.tree.get_children())
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
            self.tree.insert("", "end", iid=str(i), values=(st, r.cheat.name, len(r.lines) or "", why), tags=(tag,))
        ok = sum(1 for r in self.reports if r.ok)
        bad = sum(1 for r in self.reports if r.errors)
        parts = [f"{ok} of {len(self.reports)} cheat(s) can be exported"]
        if need:
            parts.append(f"{need} need original bytes")
        if bad:
            parts.append(f"{bad} cannot be written as {ce.FORMATS[fmt][1]} (double-click for why)")
        self.summary.configure(text=" · ".join(parts))
        self.go.configure(text=f"Export {ok} cheat(s)...", state="normal" if ok and not errs else "disabled")
        connected = bool(getattr(self.app.client, "connected", False))
        self.read_btn.configure(state="normal" if need and connected else "disabled")
        if need and not connected:
            self.read_msg.configure(text="Connect to the console with the game running to read them.")

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
        g = self.game
        if fmt in OWN:
            ext = OWN[fmt][1]
            name = cheat_pack._slug(g.title_id or g.name) + ("" if len(self.cheats) == len(g.cheats)
                                                              else "_" + cheat_pack._slug(self.cheats[0].name))
            path = filedialog.asksaveasfilename(parent=self.win, title="Export cheats", defaultextension=ext,
                                                initialdir=self._exports_dir(),
                                                initialfile=name + ext, filetypes=[(OWN[fmt][0], "*" + ext)])
            if not path:
                return
            pack = cheat_pack.build_pack([(g, self.cheats)], self.app.items)
            if fmt == "pack_json":
                Path(path).write_text(json.dumps(pack, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                Path(path).write_bytes(cheat_pack.to_file_bytes(pack))
            self.app.log_line(f"exported {len(self.cheats)} cheat(s) of {g.name} "
                              f"(+{len(pack['items'])} item list(s)) to {path}")
            self.win.destroy()
            return
        hg = self._hdr_game()
        errs, _w = ce.check_game(hg, fmt)
        ok = [r for r in self.reports if r.ok]
        if errs or not ok:
            return
        skipped = [r.cheat.name for r in self.reports if not r.ok]
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
        want = ce.default_name(hg, fmt)
        note = "" if Path(path).name == want else f"  (cheat menus expect the name {want})"
        self.app.log_line(f"exported {len(ok)} cheat(s) of {g.name} as {ext} to {path}"
                          + (f", left out {len(skipped)}" if skipped else "") + note)
        self.win.destroy()
