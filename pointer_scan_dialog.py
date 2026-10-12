"""Pointer scan window (opened from the Scanner tab)."""

from __future__ import annotations

import queue
import struct
import threading
import time
import tkinter as tk
from pathlib import Path

from app_paths import APP_DIR
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional

import pointer_scan as ps
import theme

SHOW_MAX = 5000            # rows put in the table
LIVE_ROWS = 300            # rows kept live (resolved + value read) while auto-refresh is on
VALUE_FMT = {"4 Bytes": ("<i", 4), "Float": ("<f", 4), "8 Bytes": ("<q", 8), "Double": ("<d", 8),
             "2 Bytes": ("<h", 2), "Byte": ("<B", 1)}


def _hex(text: str) -> int:
    t = text.strip()
    return int(t, 16) if t else 0


class PointerScanWindow:
    _instance: Optional["PointerScanWindow"] = None

    @classmethod
    def open(cls, app, scanner, target: Optional[int] = None) -> "PointerScanWindow":
        w = cls._instance
        if w is not None and w.win.winfo_exists():
            w.win.deiconify()
            w.win.lift()
            if target is not None:
                w.target_var.set(f"{target:X}")
            return w
        cls._instance = cls(app, scanner, target)
        return cls._instance

    def __init__(self, app, scanner, target: Optional[int]) -> None:
        self.app, self.scanner, self.root = app, scanner, app.root
        self.cli = None                         # own connection (map building blocks it for a while)
        self.pm: Optional[ps.PointerMap] = None
        self.pm_loaded = False                  # map came from a file: never replaced automatically
        self.chains: list[ps.Chain] = []
        self.live: dict[int, tuple[Optional[int], bytes]] = {}
        self.busy = False
        self._cancel = False
        self._q: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self._closed = False
        st = app.settings.get("ptrscan", {})
        self.target_var = tk.StringVar(value=f"{target:X}" if target is not None else "")
        self.level_var = tk.StringVar(value=str(st.get("level", 5)))
        if "last" not in st:          # settings from before the split: old single offset becomes the last one
            st = dict(st, last=st.get("off", "1000"), off="400")
        self.off_var = tk.StringVar(value=st.get("off", "400"))
        self.last_var = tk.StringVar(value=st.get("last", "1000"))
        self.nodes_var = tk.StringVar(value=str(st.get("nodes", "1000000")))
        self.mods_var = tk.StringVar(value=st.get("mods", ""))
        self.max_var = tk.StringVar(value=str(st.get("max", 50000)))
        self.slow_var = tk.BooleanVar(value=st.get("skip_slow", True))
        self.ro_var = tk.BooleanVar(value=st.get("readonly", False))
        self.vtype_var = tk.StringVar(value=st.get("vtype", "4 Bytes"))
        self.mode_var = tk.StringVar(value=st.get("mode", "targeted"))
        self.scans_var = tk.StringVar(value=str(st.get("scans", 8)))
        self.alias_var = tk.BooleanVar(value=st.get("alias", True))
        self.bss_var = tk.BooleanVar(value=st.get("bss", True))
        self.auto_var = tk.BooleanVar(value=True)
        self.rescan_var = tk.StringVar()
        self.map_var = tk.StringVar(value="none (only used in Full pointer map mode)")
        self.status_var = tk.StringVar(value="")
        self.count_var = tk.StringVar(value="")
        self._build()
        self.root.after(100, self._pump)
        threading.Thread(target=self._live_loop, daemon=True).start()
        if ps.np is None:
            self.status_var.set("numpy is missing - run:  pip install numpy   then restart the tool")

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        win = self.win = tk.Toplevel(self.root)
        win.title("Pointer scan")
        win.geometry(self.app.settings.get("ptrscan_geom", "1060x680"))
        win.configure(bg=theme.c("bg"))
        win.protocol("WM_DELETE_WINDOW", self.close)
        win.minsize(1000, 600)
        f = ttk.Frame(win, padding=8)
        f.pack(fill="both", expand=True)

        opt = ttk.Frame(f)
        opt.pack(fill="x")
        def field(r, c, label, var, w, tip=""):
            ttk.Label(opt, text=label).grid(row=r, column=c, sticky="w", padx=(0 if c == 0 else 12, 4), pady=2)
            e = ttk.Entry(opt, textvariable=var, width=w)
            e.grid(row=r, column=c + 1, sticky="w", pady=2)
            if tip:
                ttk.Label(opt, text=tip, style="Muted.TLabel").grid(row=r, column=c + 2, sticky="w", padx=(4, 0))
            return e
        def lab(r, c, text):
            ttk.Label(opt, text=text).grid(row=r, column=c, sticky="w", padx=(0 if c == 0 else 14, 4), pady=2)

        def ent(r, c, var, w):
            ttk.Entry(opt, textvariable=var, width=w).grid(row=r, column=c, sticky="w", pady=2)
        lab(0, 0, "Address to find (hex)"); ent(0, 1, self.target_var, 18)
        lab(0, 2, "Max level")
        ttk.Spinbox(opt, from_=1, to=8, textvariable=self.level_var, width=4).grid(row=0, column=3, sticky="w")
        lab(0, 4, "Max results"); ent(0, 5, self.max_var, 9)
        lab(1, 0, "Last offset (hex)"); ent(1, 1, self.last_var, 10)
        lab(1, 2, "Other offsets (hex)"); ent(1, 3, self.off_var, 8)
        lab(1, 4, "Max pointers / level"); ent(1, 5, self.nodes_var, 10)
        lab(2, 0, "Base modules"); ent(2, 1, self.mods_var, 18)
        ttk.Label(opt, text="empty = all modules,  e.g. eboot", style="Muted.TLabel").grid(
            row=2, column=2, columnspan=4, sticky="w", padx=(14, 0))
        ttk.Label(opt, style="Muted.TLabel", wraplength=900, justify="left",
                  text="Last offset = into the object that holds the value (can be big, e.g. 0x1C4).  Other offsets = "
                       "between pointers (usually small - keeping them small stops the search from exploding).  "
                       "Up to 8,000,000 pointers per level with the pointer-scan payload."
                  ).grid(row=3, column=0, columnspan=6, sticky="w", pady=(2, 0))

        mode = ttk.Frame(f)
        mode.pack(fill="x", pady=(8, 0))
        ttk.Label(mode, text="Mode").pack(side="left")
        ttk.Radiobutton(mode, text="Targeted - the console searches level by level (fast, no map)",
                        variable=self.mode_var, value="targeted").pack(side="left", padx=(6, 0))
        ttk.Radiobutton(mode, text="Full pointer map (slow: downloads/reads all data, reusable)",
                        variable=self.mode_var, value="map").pack(side="left", padx=(12, 0))
        srow = ttk.Frame(f)
        srow.pack(fill="x")
        ttk.Label(srow, text="Console scans per level").pack(side="left")
        ttk.Spinbox(srow, from_=1, to=64, textvariable=self.scans_var, width=4).pack(side="left", padx=4)
        ttk.Label(srow, style="Muted.TLabel",
                  text="(only without the pointer-scan payload: fewer = fewer passes, more hits to download)"
                  ).pack(side="left")
        mrow = ttk.Frame(f)
        mrow.pack(fill="x", pady=(4, 0))
        ttk.Label(mrow, text="Pointer map:").pack(side="left")
        ttk.Label(mrow, textvariable=self.map_var, style="Muted.TLabel").pack(side="left", padx=6)
        for text, cmd in (("Save map…", self.on_save_map), ("Load map…", self.on_load_map),
                          ("Build new map", self.on_build_map)):
            ttk.Button(mrow, text=text, style="Small.TButton", command=cmd).pack(side="right", padx=(4, 0))
        orow = ttk.Frame(f)
        orow.pack(fill="x")
        ttk.Checkbutton(orow, text="skip GPU / slow memory", variable=self.slow_var).pack(side="left")
        ttk.Checkbutton(orow, text="also read-only data", variable=self.ro_var).pack(side="left", padx=12)
        ttk.Checkbutton(orow, text="fast memory access (aliasing read engine)",
                        variable=self.alias_var).pack(side="left")
        ttk.Checkbutton(orow, text="count the unnamed region after a module as its globals (.bss)",
                        variable=self.bss_var).pack(side="left", padx=12)

        run = ttk.Frame(f)
        run.pack(fill="x", pady=(8, 4))
        self.scan_btn = ttk.Button(run, text="Scan", style="Accent.TButton", width=10, command=self.on_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(run, text="Cancel", command=self.on_cancel).pack(side="left", padx=6)
        self.bar = ttk.Progressbar(run, mode="determinate", length=220, maximum=1.0)
        self.bar.pack(side="left", padx=8)
        ttk.Label(run, textvariable=self.status_var, style="Muted.TLabel").pack(side="left", fill="x")

        tf = ttk.Frame(f)
        tf.pack(fill="both", expand=True)
        cols = ("base", "offs", "lvl", "addr", "value")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="extended")
        for c, t, w, st in (("base", "Base", 210, False), ("offs", "Offsets", 260, True), ("lvl", "Lvl", 40, False),
                            ("addr", "Points to", 150, False), ("value", "Value", 120, False)):
            self.tree.heading(c, text=t, anchor="w")
            self.tree.column(c, width=w, stretch=st, anchor="w")
        theme.stripe(self.tree)
        self.tree.tag_configure("bad", foreground=theme.c("muted"))
        self.tree.tag_configure("hit", foreground=theme.c("ok"))
        ys = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.bind("<Button-3>", self._menu)
        self.tree.bind("<Double-1>", lambda e: self.add_selected())

        bot = ttk.Frame(f)
        bot.pack(fill="x", pady=(6, 0))
        ttk.Label(bot, text="Value as").pack(side="left")
        ttk.Combobox(bot, textvariable=self.vtype_var, values=list(VALUE_FMT), state="readonly",
                     width=8).pack(side="left", padx=4)
        ttk.Checkbutton(bot, text="live", variable=self.auto_var).pack(side="left", padx=(6, 16))
        ttk.Label(bot, text="New address (hex)").pack(side="left")
        ttk.Entry(bot, textvariable=self.rescan_var, width=16).pack(side="left", padx=4)
        ttk.Button(bot, text="Rescan", command=self.on_rescan).pack(side="left")
        ttk.Button(bot, text="Load results…", style="Small.TButton", command=self.on_load_results).pack(side="right")
        ttk.Button(bot, text="Save results…", style="Small.TButton",
                   command=self.on_save_results).pack(side="right", padx=4)
        ttk.Label(bot, textvariable=self.count_var, style="Muted.TLabel").pack(side="right", padx=8)
        ttk.Label(f, style="Muted.TLabel", wraplength=940, justify="left",
                  text="Green = still points to the address.  Rescan after restarting the game or reloading: "
                       "find the value again, type its new address and press Rescan - only chains that "
                       "lead there are kept.  Double-click (or right-click) a chain to add it to the "
                       "address list; it is re-followed live, so it keeps working after a restart.").pack(
            anchor="w", pady=(6, 0))

    # ------------------------------------------------------------------ plumbing
    def _post(self, fn: Callable[[], None]) -> None:
        self._q.put(fn)

    def _pump(self) -> None:
        if self._closed:
            return
        try:
            while True:
                self._q.get_nowait()()
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def _progress(self, msg: str, frac: float) -> None:
        def ui() -> None:
            self.status_var.set(msg)
            if frac >= 0:
                self.bar.configure(mode="determinate")
                self.bar["value"] = frac
        self._post(ui)

    def _conn(self):
        main = self.app.client
        if not main.connected:
            raise RuntimeError("connect to the console first")
        if self.cli is None or not self.cli.connected or self.cli.host != main.host:
            if self.cli is not None:
                self.cli.close()
            self.cli = main.clone()
            self.cli.timeout = 30.0
        return self.cli

    def _pid(self) -> int:
        pid = self.scanner._pid_quiet()
        if not pid:
            raise RuntimeError("pick the game process (PID) first")
        return pid

    def _run(self, fn: Callable[[], None], msg: str) -> None:
        if self.busy:
            self.app.log_line("pointer scan: busy - wait or press Cancel")
            return
        self.busy, self._cancel = True, False
        self.status_var.set(msg)
        self.bar["value"] = 0
        self.scan_btn.configure(state="disabled")

        def work() -> None:
            try:
                fn()
            except ps.Cancelled:
                self._post(lambda: self.status_var.set("cancelled"))
            except Exception as exc:
                self._post(lambda e=exc: (self.status_var.set(f"error: {e}"),
                                          self.app.log_line(f"pointer scan: {e}")))
            finally:
                self._post(self._idle)
        threading.Thread(target=work, daemon=True).start()

    def _idle(self) -> None:
        self.busy = False
        self.scan_btn.configure(state="normal")

    def _save_opts(self) -> None:
        self.app.settings["ptrscan"] = {"level": self.level_var.get(), "off": self.off_var.get(),
                                        "last": self.last_var.get(), "nodes": self.nodes_var.get(),
                                        "mods": self.mods_var.get(), "max": self.max_var.get(),
                                        "skip_slow": self.slow_var.get(), "readonly": self.ro_var.get(),
                                        "vtype": self.vtype_var.get(), "mode": self.mode_var.get(),
                                        "scans": self.scans_var.get(), "alias": self.alias_var.get(),
                                        "bss": self.bss_var.get()}

    def _map_text(self) -> None:
        pm = self.pm
        if pm is None:
            self.map_var.set("none")
            return
        when = time.strftime("%H:%M:%S", time.localtime(pm.created))
        self.map_var.set(f"{len(pm):,} pointers  ·  pid {pm.pid}  {pm.title}  ·  made {when}")

    # ------------------------------------------------------------------ actions
    def on_cancel(self) -> None:
        self._cancel = True
        if self.busy:                              # map building: ask the console to stop its scan too
            pid = self.scanner._pid_quiet()

            def work() -> None:
                try:
                    c = self.app.client.clone()
                    try:
                        c.turbo_cancel(pid)
                    finally:
                        c.close()
                except Exception:
                    pass
            threading.Thread(target=work, daemon=True).start()

    def _build_map_work(self, pid: int) -> None:
        cli = self._conn()
        title = ""
        try:
            title = next((p.name for p in cli.list_processes() if p.pid == pid), "")
        except Exception:
            pass
        t0 = time.monotonic()
        pm = ps.build_map(cli, pid, title, self.slow_var.get(), self.ro_var.get(),
                          progress=self._progress, cancel=lambda: self._cancel, alias=self.alias_var.get())
        self.pm, self.pm_loaded = pm, False
        dt = time.monotonic() - t0
        self._post(lambda: (self._map_text(), self.app.log_line(
            f"pointer scan: map of {len(pm):,} pointers in {dt:.1f}s")))

    def on_build_map(self) -> None:
        try:
            ps.need_numpy()
            pid = self._pid()
        except Exception as exc:
            self.status_var.set(str(exc))
            return
        self._save_opts()
        self._run(lambda: self._build_map_work(pid), "building pointer map…")

    def on_scan(self) -> None:
        try:
            ps.need_numpy()
            target = _hex(self.target_var.get())
            if not target:
                raise ValueError("type the address to find")
            level = max(1, min(8, int(self.level_var.get())))
            max_off = _hex(self.off_var.get()) or 0x400
            last_off = _hex(self.last_var.get()) or max_off
            nodes = max(1000, min(8_000_000, int(self.nodes_var.get().replace(",", "") or 1_000_000)))
            if max_off > 0x100000 or last_off > 0x100000:
                raise ValueError("offsets above 0x100000 are not supported")
            max_res = max(1, int(self.max_var.get().replace(",", "") or 50000))
            mods = [m for m in self.mods_var.get().replace(";", ",").split(",") if m.strip()]
            cur_pid = self.scanner._pid_quiet()
            targeted = self.mode_var.get() == "targeted"
            scans = max(1, min(64, int(self.scans_var.get() or 8)))
            rebuild = not targeted and (self.pm is None or (not self.pm_loaded and cur_pid and self.pm.pid != cur_pid))
            if (rebuild or targeted) and not cur_pid:
                raise RuntimeError("pick the game process (PID) first")
        except Exception as exc:
            self.status_var.set(str(exc))
            return
        self._save_opts()

        def work() -> None:
            if targeted:
                t0 = time.monotonic()
                res = ps.search_live(self._conn(), cur_pid, target, level, max_off, mods or None, max_res,
                                     self.slow_var.get(), self.ro_var.get(), scans,
                                     max_nodes=nodes, progress=self._progress, cancel=lambda: self._cancel,
                                     alias=self.alias_var.get(), last_off=last_off,
                                     include_bss=self.bss_var.get())
                dt = time.monotonic() - t0
                msg = (f"{len(res.chains):,} chain(s) in {dt:.0f}s" + (" (max results reached)" if res.truncated else "")
                       + (f"  ·  pointers per level {', '.join(f'{n:,}' for n in res.per_level)}" if res.per_level else "")
                       + (f"  ·  {res.note}" if res.note else ""))
                self._post(lambda: (self._set_chains(res.chains), self.status_var.set(msg),
                                    self.bar.configure(value=1.0), self.app.log_line(f"pointer scan: {msg}"), [self.app.log_line(f"pointer scan: base region {x}") for x in res.module_notes]))
                return
            if rebuild:
                self._build_map_work(cur_pid)
            pm = self.pm
            t0 = time.monotonic()
            res = ps.search(pm, target, level, max_off, mods or None, max_res, max_nodes=nodes,
                            progress=self._progress, cancel=lambda: self._cancel, last_off=last_off,
                            include_bss=self.bss_var.get())
            dt = time.monotonic() - t0
            msg = (f"{len(res.chains):,} chain(s) in {dt:.1f}s" + (" (max results reached)" if res.truncated else "")
                   + (f" - {res.note}" if res.note else ""))
            self._post(lambda: (self._set_chains(res.chains), self.status_var.set(msg),
                                self.bar.configure(value=1.0), self.app.log_line(f"pointer scan: {msg}"), [self.app.log_line(f"pointer scan: base region {x}") for x in res.module_notes]))
        self._run(work, "searching…")

    def on_rescan(self) -> None:
        try:
            new = _hex(self.rescan_var.get())
            if not new:
                raise ValueError("type the value's new address")
            pid = self._pid()
        except Exception as exc:
            self.status_var.set(str(exc))
            return
        chains = list(self.chains)
        if not chains:
            self.status_var.set("nothing to rescan")
            return

        def work() -> None:
            cli = self._conn()
            maps = cli.maps(pid)
            keep: list[ps.Chain] = []
            for s in range(0, len(chains), 20000):
                if self._cancel:
                    raise ps.Cancelled()
                part = chains[s : s + 20000]
                for c, a in zip(part, ps.resolve(cli, pid, part, maps)):
                    if a == new:
                        keep.append(c)
                self._progress(f"rescan: {min(s + 20000, len(chains)):,} / {len(chains):,}",
                               min(1.0, (s + 20000) / len(chains)))
            msg = f"rescan: kept {len(keep):,} of {len(chains):,} chain(s)"
            self._post(lambda: (self._set_chains(keep), self.target_var.set(f"{new:X}"),
                                self.status_var.set(msg), self.app.log_line(f"pointer scan: {msg}")))
        self._run(work, "rescanning…")

    # ------------------------------------------------------------------ results table
    def _set_chains(self, chains: list[ps.Chain]) -> None:
        self.chains = chains
        self.live.clear()
        self.tree.delete(*self.tree.get_children())
        for i, c in enumerate(chains[:SHOW_MAX]):
            self.tree.insert("", "end", iid=str(i), tags=("odd",) if i % 2 else (), values=(
                f"{c.module}+{c.base_off:X}", " → ".join(f"{o:X}" for o in c.offsets), c.level, "", ""))
        shown = min(len(chains), SHOW_MAX)
        self.count_var.set(f"{len(chains):,} chain(s)" + (f", showing {shown:,}" if shown < len(chains) else ""))

    def _sel(self) -> list[ps.Chain]:
        return [self.chains[int(i)] for i in self.tree.selection() if int(i) < len(self.chains)]

    def _menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        sel = self._sel()
        if not sel:
            return
        c = sel[0]
        addr = self.live.get(int(self.tree.selection()[0]), (None, b""))[0]
        m = tk.Menu(self.win, tearoff=0)
        m.add_command(label=f"Add {len(sel)} to address list", command=self.add_selected)
        m.add_command(label="Copy as cheat expression", command=lambda: self._copy(c.expr()))
        m.add_command(label="Copy Cheat Engine style", command=lambda: self._copy(c.ce_text()))
        m.add_separator()
        m.add_command(label="Browse where it points (hex)", state="normal" if addr else "disabled",
                      command=lambda: self.app._hex_goto_value(addr & ~0xF))
        m.add_command(label="Delete from results", command=self.delete_selected)
        m.tk_popup(event.x_root, event.y_root)

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.app.log_line(f"copied: {text}")

    def add_selected(self) -> None:
        sel = self._sel()
        if sel:
            self.scanner.add_pointer_entries(sel, self.vtype_var.get())

    def delete_selected(self) -> None:
        drop = {int(i) for i in self.tree.selection()}
        self._set_chains([c for i, c in enumerate(self.chains) if i not in drop])

    # ------------------------------------------------------------------ live values
    def _live_loop(self) -> None:
        maps, maps_t = None, 0.0
        while not self._closed:
            time.sleep(1.2)
            try:
                if self.busy or not self.auto_var.get() or not self.chains or not self.app.client.connected:
                    continue
                if not self.win.winfo_viewable():
                    continue
                pid = self.scanner._pid_quiet()
                if not pid:
                    continue
                rows = self._visible_rows()
                if not rows:
                    continue
                chains = [self.chains[i] for i in rows]
                fmt, size = VALUE_FMT.get(self.vtype_var.get(), ("<i", 4))
                cli = self._conn()
                if maps is None or time.monotonic() - maps_t > 5:
                    maps, maps_t = cli.maps(pid), time.monotonic()
                addrs = ps.resolve(cli, pid, chains, maps)
                ok = [(i, a) for i, a in zip(rows, addrs) if a]
                datas = cli.read_multi(pid, [(a, size) for _i, a in ok]) if ok else []
                vals = {i: d for (i, _a), d in zip(ok, datas)}
                target = _hex(self.target_var.get() or "0")
                self._post(lambda: self._show_live(rows, addrs, vals, fmt, size, target))
            except Exception:
                maps = None
                continue

    def _visible_rows(self) -> list[int]:
        out: list[int] = []
        if not self.chains:
            return out
        q: "queue.Queue[list[int]]" = queue.Queue()

        def ui() -> None:
            try:
                top = self.tree.yview()[0]
                first = int(top * min(len(self.chains), SHOW_MAX))
                q.put(list(range(max(0, first - 20), min(min(len(self.chains), SHOW_MAX), first + LIVE_ROWS))))
            except Exception:
                q.put([])
        self._post(ui)
        try:
            return q.get(timeout=2)
        except queue.Empty:
            return out

    def _show_live(self, rows, addrs, vals, fmt, size, target) -> None:
        for i, a in zip(rows, addrs):
            iid = str(i)
            if not self.tree.exists(iid):
                continue
            d = vals.get(i, b"")
            self.live[i] = (a, d)
            if a is None:
                txt_a, txt_v, tag = "??", "", "bad"
            else:
                txt_a = f"{a:X}"
                try:
                    v = struct.unpack(fmt, d[:size])[0]
                    txt_v = f"{v:.6g}" if isinstance(v, float) else str(v)
                except struct.error:
                    txt_v = "??"
                tag = "hit" if a == target else ""
            tags = tuple(t for t in (("odd" if i % 2 else ""), tag) if t)
            self.tree.set(iid, "addr", txt_a)
            self.tree.set(iid, "value", txt_v)
            self.tree.item(iid, tags=tags)

    # ------------------------------------------------------------------ files
    def _dir(self) -> Path:
        d = APP_DIR / "pointerscans"
        d.mkdir(exist_ok=True)
        return d

    def on_save_map(self) -> None:
        if self.pm is None:
            self.status_var.set("no pointer map to save")
            return
        path = filedialog.asksaveasfilename(parent=self.win, initialdir=str(self._dir()), defaultextension=".ptrmap",
                                            initialfile=time.strftime("map_%Y-%m-%d_%H%M%S.ptrmap"),
                                            filetypes=[("Pointer map", "*.ptrmap")])
        if path:
            pm = self.pm
            self._run(lambda: (pm.save(Path(path)), self._post(lambda: self.status_var.set(f"saved {path}"))),
                      "saving map…")

    def on_load_map(self) -> None:
        path = filedialog.askopenfilename(parent=self.win, initialdir=str(self._dir()),
                                          filetypes=[("Pointer map", "*.ptrmap"), ("All", "*.*")])
        if not path:
            return

        def work() -> None:
            pm = ps.PointerMap.load(Path(path))
            self.pm, self.pm_loaded = pm, True
            self._post(lambda: (self._map_text(), self.status_var.set(f"loaded {Path(path).name}")))
        self._run(work, "loading map…")

    def on_save_results(self) -> None:
        if not self.chains:
            self.status_var.set("no results to save")
            return
        path = filedialog.asksaveasfilename(parent=self.win, initialdir=str(self._dir()), defaultextension=".ptrs",
                                            initialfile=time.strftime("ptrs_%Y-%m-%d_%H%M%S.ptrs"),
                                            filetypes=[("Pointer scan results", "*.ptrs")])
        if path:
            ps.save_results(Path(path), self.chains, {"target": self.target_var.get(),
                                                      "title": self.pm.title if self.pm else ""})
            self.status_var.set(f"saved {len(self.chains):,} chain(s)")

    def on_load_results(self) -> None:
        path = filedialog.askopenfilename(parent=self.win, initialdir=str(self._dir()),
                                          filetypes=[("Pointer scan results", "*.ptrs"), ("All", "*.*")])
        if not path:
            return
        try:
            chains, info = ps.load_results(Path(path))
        except Exception as exc:
            messagebox.showerror("Pointer scan", str(exc), parent=self.win)
            return
        self._set_chains(chains)
        if info.get("target"):
            self.target_var.set(str(info["target"]))
        self.status_var.set(f"loaded {len(chains):,} chain(s) - Rescan with the current address to check them")

    def close(self) -> None:
        self._closed = True
        self._cancel = True
        self._save_opts()
        try:
            self.app.settings["ptrscan_geom"] = self.win.geometry()
        except tk.TclError:
            pass
        if self.cli is not None:
            try:
                self.cli.close()
            except Exception:
                pass
        self.win.destroy()
        PointerScanWindow._instance = None
