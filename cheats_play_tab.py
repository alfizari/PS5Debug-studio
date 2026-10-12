"""Cheats tab: the everyday surface - pick a game, flip cheats on and off.
Building and editing cheats happens in the Cheat Editor tab; both share one store.

Layout: a slim game list on the left (with how many cheats are ON), one compact row per
cheat on the right.  Nothing is rebuilt when a cheat runs - only that row is restyled -
so scroll position and typed inputs stay put."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from cheats import Game
from bulk_items import BulkItemsDialog
from cheats_store import CheatsStore
from items import SearchCombobox
from scrollable import ScrollFrame
import theme  # noqa: E402

ALL = "__all__"


class CheatsPlayTab:
    def __init__(self, parent: ttk.Frame, app, store: CheatsStore) -> None:
        self.app = app
        self.store = store
        self.search = tk.StringVar()
        self.info = tk.StringVar(value="")
        self._search_job = None
        self.search.trace_add("write", lambda *_: self._search_later())
        self._rows: dict = {}                      # cheat key -> widgets of its row
        self._sel: Optional[str] = None            # selected game path (or ALL while searching)
        self._build(parent)
        store.on_change(self.refresh)
        store.on_state(self.update_states)
        app.items.on_change.append(self.refresh)
        self.refresh()

    def _search_later(self) -> None:
        if self._search_job is not None:
            self.app.root.after_cancel(self._search_job)
        self._search_job = self.app.root.after(250, self._search_now)

    def _search_now(self) -> None:
        self._search_job = None
        self.refresh()

    # ------------------------------------------------------------------ UI
    def _build(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent, padding=(8, 6, 8, 4))
        top.pack(fill="x")
        ttk.Label(top, text="🔎").pack(side="left")
        ttk.Entry(top, textvariable=self.search, width=26).pack(side="left", padx=(2, 12))
        ttk.Label(top, text="PID").pack(side="left")
        ttk.Entry(top, textvariable=self.app.pid_var, width=8).pack(side="left", padx=(4, 10))
        ttk.Checkbutton(top, text="verify title id", variable=self.store.verify).pack(side="left")
        for text, cmd in (("Import…", lambda: self.app.cheats_editor.on_import()),
                          ("Reload", self.store.reload),
                          ("Python script…", lambda: self.app.open_script_window())):
            ttk.Button(top, text=text, style="Small.TButton", command=cmd).pack(side="right", padx=(4, 0))

        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True, padx=8)
        left = ttk.Frame(body, width=240)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self.games_tv = ttk.Treeview(left, columns=("on",), show="tree headings", selectmode="browse")
        self.games_tv.heading("#0", text="Game", anchor="w")
        self.games_tv.heading("on", text="ON", anchor="e")
        self.games_tv.column("#0", width=180, stretch=True)
        self.games_tv.column("on", width=40, anchor="e", stretch=False)
        self.games_tv.tag_configure("active", foreground=theme.c("ok"))
        self.games_tv.pack(fill="both", expand=True)
        self.games_tv.bind("<<TreeviewSelect>>", lambda _e: self._on_pick())

        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))
        head = ttk.Frame(right)
        head.pack(fill="x", pady=(0, 4))
        self.title_lbl = ttk.Label(head, text="", font=("Segoe UI", 12, "bold"))
        self.title_lbl.pack(side="left")
        self.sub_lbl = ttk.Label(head, text="", style="Muted.TLabel")
        self.sub_lbl.pack(side="left", padx=8)
        self.alloff_btn = ttk.Button(head, text="Turn all off", style="Small.TButton", command=self.on_all_off)
        self.alloff_btn.pack(side="right", padx=(4, 0))
        self.find_btn = ttk.Button(head, text="Find process", style="Small.TButton", command=self.on_find)
        self.find_btn.pack(side="right", padx=(4, 0))
        ttk.Separator(right).pack(fill="x")
        scroll = ScrollFrame(right, horizontal=False)
        scroll.pack(fill="both", expand=True)
        self.list_frame = scroll.body
        self.scroll = scroll

        ttk.Label(parent, textvariable=self.info, style="Muted.TLabel", padding=(10, 3), wraplength=1200,
                  justify="left").pack(fill="x")

    # ------------------------------------------------------------------ games list
    def _matches(self) -> list[tuple[Game, list]]:
        q = self.search.get().strip().lower()
        out = []
        for game in self.store.games:
            hit = q in f"{game.name} {game.title_id}".lower()
            cheats = [c for c in game.cheats if not q or hit or q in c.name.lower()
                      or q in (c.description or "").lower()]
            if q and not hit and not cheats:
                continue
            out.append((game, cheats))
        return out

    def refresh(self) -> None:
        tv = self.games_tv
        tv.delete(*tv.get_children())
        q = self.search.get().strip()
        matches = self._matches()
        if q and len(matches) > 1:
            tv.insert("", "end", iid=ALL, text=f"All matches ({sum(len(c) for _g, c in matches)})")
        for game, cheats in matches:
            tv.insert("", "end", iid=str(game.path), text=game.name, values=("",))
        self._update_counts()
        keep = self._sel if self._sel and tv.exists(self._sel) else None
        if keep is None and tv.get_children():
            keep = ALL if (q and tv.exists(ALL)) else tv.get_children()[0]
        if keep:
            tv.selection_set(keep)
            tv.see(keep)
        self._show(keep)

    def _update_counts(self) -> None:
        tv = self.games_tv
        for game in self.store.games:
            iid = str(game.path)
            if not tv.exists(iid):
                continue
            on = sum(1 for c in game.cheats if self.store.is_enabled(game, c))
            tv.set(iid, "on", str(on) if on else "")
            tv.item(iid, tags=("active",) if on else ())

    def _on_pick(self) -> None:
        sel = self.games_tv.selection()
        iid = sel[0] if sel else None
        if iid != self._sel:
            self._show(iid)

    def _game(self, path: Optional[str]) -> Optional[Game]:
        return next((g for g in self.store.games if str(g.path) == path), None)

    # ------------------------------------------------------------------ cheats list
    def _show(self, iid: Optional[str]) -> None:
        self._sel = iid
        self._rows.clear()
        for w in self.list_frame.winfo_children():
            w.destroy()
        self.scroll.canvas.yview_moveto(0)
        if iid is None:
            self.title_lbl.configure(text="")
            self.sub_lbl.configure(text="")
            msg = ("No cheats match your search." if self.search.get().strip() else
                   "No cheats yet - build one in the Cheat Editor tab, or Import… a cheat file.")
            ttk.Label(self.list_frame, text=msg, padding=20, style="Muted.TLabel").pack(anchor="w")
            return
        if iid == ALL:
            self.title_lbl.configure(text="Search results")
            self.find_btn.pack_forget()
            n = 0
            for game, cheats in self._matches():
                if not cheats:
                    continue
                ttk.Label(self.list_frame, text=game.name, font=("Segoe UI", 9, "bold"),
                          foreground=theme.c("muted")).pack(anchor="w", pady=(8, 0))
                for k, c in enumerate(cheats):
                    self._row(game, c, n + k)
                n += len(cheats)
            self._update_head()
            return
        game = self._game(iid)
        if game is None:
            return
        self.title_lbl.configure(text=game.name)
        self.find_btn.pack(side="right", padx=(4, 0))
        q = self.search.get().strip()
        cheats = next((c for g, c in self._matches() if g is game), game.cheats) if q else game.cheats
        for i, c in enumerate(cheats):
            self._row(game, c, i)
        self._update_head()

    def _update_head(self) -> None:
        if self._sel in (None, ALL):
            self.sub_lbl.configure(text="")
            return
        game = self._game(self._sel)
        if not game:
            return
        on = sum(1 for c in game.cheats if self.store.is_enabled(game, c))
        parts = [p for p in (game.title_id, f"v{game.version}" if game.version else "",
                             f"{len(game.cheats)} cheats", f"{on} ON" if on else "") if p]
        self.sub_lbl.configure(text="  ·  ".join(parts))
        self.alloff_btn.configure(state="normal" if on else "disabled")

    def _row(self, game: Game, cheat, i: int) -> None:
        key = self.store.key(game, cheat)
        bg = theme.c("stripe") if i % 2 else theme.c("bg")
        row = tk.Frame(self.list_frame, bg=bg)
        row.pack(fill="x")
        btn = ttk.Button(row, width=6, command=lambda g=game, c=cheat: self.store.run(g, c))
        btn.pack(side="left", padx=(4, 8), pady=2)
        name = tk.Label(row, text=cheat.name, bg=bg, fg=theme.c("fg"), anchor="w", font=("Segoe UI", 10))
        name.pack(side="left")
        tip = cheat.description or ""
        if tip:
            info = tk.Label(row, text="ⓘ", bg=bg, fg=theme.c("muted"), cursor="question_arrow")
            info.pack(side="left", padx=4)
            for wdg in (info, name):
                wdg.bind("<Enter>", lambda _e, t=tip, n=cheat.name: self.info.set(f"{n}:  {t}"))
                wdg.bind("<Leave>", lambda _e: self.info.set(""))
        reapply = None
        if cheat.mode == "toggle":
            reapply = ttk.Button(row, text="⟳", width=3, style="Tool.TButton",
                                 command=lambda g=game, c=cheat: self.store.run(g, c, force_on=True))
        for p in reversed(cheat.params or []):
            self._param(row, key, game, cheat, p, bg)
        self._rows[key] = {"btn": btn, "name": name, "reapply": reapply, "game": game, "cheat": cheat}
        self._style(key)

    def _param(self, row, key, game, cheat, p: dict, bg: str) -> None:
        var = tk.StringVar(value=self.store.param_var_text(key, p))
        var.trace_add("write", lambda *_, k=key, n=p["name"], v=var: self.store.set_param_text(k, n, v.get()))
        lst = p.get("items", "")
        entries = self.app.items.items(lst) if lst else {}
        if entries:
            ttk.Button(row, text="All…", width=5, style="Tool.TButton",
                       command=lambda g=game, c=cheat, pp=p: BulkItemsDialog(self.app, self.store, g, c, pp)
                       ).pack(side="right", padx=(0, 4))
            w = SearchCombobox(row, textvariable=var, width=22)
            w.set_values(sorted(entries, key=str.lower))
        else:
            w = ttk.Entry(row, textvariable=var, width=10)
        w.pack(side="right", padx=(0, 4), pady=2)
        tk.Label(row, text=p.get("label") or p["name"], bg=bg, fg=theme.c("muted"),
                 font=("Segoe UI", 8)).pack(side="right", padx=(8, 2))

    def _style(self, key) -> None:
        r = self._rows.get(key)
        if not r:
            return
        cheat = r["cheat"]
        on = self.store.is_enabled(r["game"], cheat)
        if cheat.mode == "toggle":
            r["btn"].configure(text="ON" if on else "OFF", style="Accent.TButton" if on else "TButton")
            if on:
                r["reapply"].pack(side="left", padx=2, after=r["name"])
            else:
                r["reapply"].pack_forget()
        else:
            r["btn"].configure(text="Run", style="TButton")
        r["name"].configure(font=("Segoe UI", 10, "bold") if on else ("Segoe UI", 10),
                            fg=theme.c("ok") if on else theme.c("fg"))

    def update_states(self) -> None:
        """A cheat ran / was toggled: restyle rows in place (no rebuild)."""
        for key in list(self._rows):
            self._style(key)
        self._update_counts()
        self._update_head()

    # ------------------------------------------------------------------ actions
    def on_find(self) -> None:
        game = self._game(self._sel)
        if game:
            self.store.find_process(game)

    def on_all_off(self) -> None:
        game = self._game(self._sel)
        if not game:
            return
        self.store.turn_all_off(game)

    # kept for callers of the old API
    def set_all_collapsed(self, hide: bool) -> None:
        pass
