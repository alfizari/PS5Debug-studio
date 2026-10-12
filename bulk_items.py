"""'Add all items': run one cheat once per entry of an item list.

Used by the Cheats tab and the Cheat Editor next to every input that is linked
to an item list.  The cheat runs with the item id of entry 1 first, then 2,
and so on, in the order they appear in the JSON file.
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk


class BulkItemsDialog:
    def __init__(self, app, store, game, cheat, param: dict) -> None:
        self.app, self.store, self.game, self.cheat, self.param = app, store, game, cheat, param
        self.lst = param.get("items", "")
        self.items = list(app.items.items(self.lst).items())   # [(name, id)] in file order
        self.cancel = threading.Event()
        self.running = False
        if not self.items:
            messagebox.showerror("Add all items", f"Item list '{self.lst}' is empty or not loaded.")
            return

        win = tk.Toplevel(app.root)
        self.win = win
        win.title(f"Add all items - {cheat.name}")
        win.geometry("600x400")
        win.transient(app.root)
        win.protocol("WM_DELETE_WINDOW", self.on_close)

        f = ttk.Frame(win, padding=10)
        f.pack(fill="both", expand=True)
        label = param.get("label") or param["name"]
        ttk.Label(f, wraplength=520, justify="left",
                  text=f"Runs '{cheat.name}' once for every entry of '{self.lst}' ({len(self.items)} items), "
                       f"setting '{label}' to each id in file order: item 1 first, then 2, and so on. "
                       "Other inputs keep the values typed in the Cheats tab.").pack(anchor="w")

        g = ttk.Frame(f)
        g.pack(fill="x", pady=8)
        self.start = tk.StringVar(value="1")
        self.end = tk.StringVar(value=str(len(self.items)))
        self.delay = tk.StringVar(value="250")
        self.stop_err = tk.BooleanVar(value=True)
        for c, (lbl, var, w) in enumerate((("From item #", self.start, 7), ("To item #", self.end, 7),
                                           ("Delay between (ms)", self.delay, 7))):
            ttk.Label(g, text=lbl).grid(row=0, column=2 * c, sticky="w", padx=(0, 4))
            ttk.Entry(g, textvariable=var, width=w).grid(row=0, column=2 * c + 1, padx=(0, 12))
        self.stop_err = tk.BooleanVar(value=False)
        # OFF by default: a call that reported an error may still have run in the game
        # (e.g. the reply was lost), and retrying it would add the item twice.
        self.retry_failed = tk.BooleanVar(value=False)
        self.max_retries = tk.StringVar(value="1")
        plan = store.batch_plan(cheat, param["name"])
        self.batch = tk.StringVar(value="8" if plan else "1")

        ttk.Checkbutton(
            f,
            text="Stop at the first error",
            variable=self.stop_err
        ).pack(anchor="w")

        retry_frame = ttk.Frame(f)
        retry_frame.pack(anchor="w", pady=4)

        ttk.Checkbutton(
            retry_frame,
            text="Retry failed items (may duplicate an item)",
            variable=self.retry_failed
        ).pack(side="left")

        ttk.Label(retry_frame, text="Maximum retries:").pack(
            side="left", padx=(10, 4)
        )

        ttk.Entry(
            retry_frame,
            textvariable=self.max_retries,
            width=5
        ).pack(side="left")

        brow = ttk.Frame(f)
        brow.pack(anchor="w", pady=4)
        ttk.Label(brow, text="Items per remote call:").pack(side="left")
        ttk.Entry(brow, textvariable=self.batch, width=5).pack(side="left", padx=4)
        ttk.Label(brow, style="Muted.TLabel",
                  text=("chains items into one call (fewer hijacks)"
                        if plan else "(this cheat is not a simple code+call, so 1 at a time)")).pack(side="left")

        self.bar = ttk.Progressbar(f, maximum=len(self.items))
        self.bar.pack(fill="x", pady=(10, 2))
        self.msg = tk.StringVar(value="Ready.")
        ttk.Label(f, textvariable=self.msg, wraplength=520, justify="left").pack(anchor="w")

        bt = ttk.Frame(win, padding=(10, 0, 10, 10))
        bt.pack(fill="x")
        self.btn_start = ttk.Button(bt, text="Start", command=self.on_start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(bt, text="Stop", command=self.cancel.set, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        ttk.Button(bt, text="Close", command=self.on_close).pack(side="right")

    def on_start(self) -> None:
        try:
            retries = int(self.max_retries.get().strip())
            if retries < 0:
                raise ValueError("Maximum retries cannot be negative.")
            batch = int(self.batch.get().strip() or "1")
            if not 1 <= batch <= 256:
                raise ValueError("Items per remote call must be 1..256")
        except ValueError as exc:
            messagebox.showerror("Add all items", str(exc), parent=self.win)
            return
        try:
            a, b = int(self.start.get().strip(), 0), int(self.end.get().strip(), 0)
            delay = int(self.delay.get().strip() or "0", 0)
            if not 1 <= a <= b <= len(self.items):
                raise ValueError(f"'From' and 'To' must satisfy 1 <= from <= to <= {len(self.items)}")
            if delay < 0:
                raise ValueError("delay cannot be negative")
        except ValueError as exc:
            messagebox.showerror("Add all items", str(exc), parent=self.win)
            return
        chosen = self.items[a - 1 : b]
        if len(chosen) > 20 and not messagebox.askyesno(
                "Add all items", f"Run '{self.cheat.name}' {len(chosen)} times?", parent=self.win):
            return
        self.cancel.clear()
        self.bar.configure(maximum=len(chosen), value=0)
        started = self.store.run_items(
            self.game,
            self.cheat,
            self.param["name"],
            chosen,
            delay_ms=delay,
            stop_on_error=self.stop_err.get(),
            cancel=self.cancel,
            on_progress=self._progress,
            on_done=self._done,
            retry_failed=self.retry_failed.get(),
            max_retries=retries,
            batch=batch,
        )
        if started:
            self.running = True
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")

    def _alive(self) -> bool:
        try:
            return bool(self.win.winfo_exists())
        except tk.TclError:
            return False

    def _progress(self, i: int, total: int, name: str, err) -> None:
        if not self._alive():
            return
        self.bar.configure(value=i - (1 if err is None else 0))
        self.msg.set(f"[{i}/{total}] {name}" + (f"   FAILED: {err}" if err else ""))

    def _done(self, ok: int, failed: int, cancelled: bool) -> None:
        self.running = False
        if not self._alive():
            return
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.bar.configure(value=ok + failed)
        self.msg.set(f"Finished: {ok} ok, {failed} failed" + (" (stopped)" if cancelled else "") + ".")

    def on_close(self) -> None:
        if self.running:
            self.cancel.set()      # the run stops after the current item
        self.win.destroy()
