"""Function logger window: every call of a function, live, without stopping the game."""

from __future__ import annotations

import csv
import queue
import struct
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk
from typing import Optional

import func_logger as fl
import theme

MAX_ROWS = 5000
COLS = ("n", "t", "caller", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "xmm0")


class FuncLoggerWindow:
    def __init__(self, app, addr: Optional[int] = None) -> None:
        self.app, self.root = app, app.root
        self.cli = None                       # own connection: polling never waits behind other work
        self.lg: Optional[fl.FuncLogger] = None
        self.calls: list[fl.Call] = []
        self.groups: dict[int, list] = {}     # return address -> [count, last call]
        self._q: "queue.Queue" = queue.Queue()
        self._closed = False
        self._rate: list[tuple[float, int]] = []
        self.addr_var = tk.StringVar(value=f"0x{addr:X}" if addr else "")
        self.where_var = tk.StringVar()
        self.stat_var = tk.StringVar(value="not running")
        self.group_var = tk.BooleanVar(value=False)
        self.pause_var = tk.BooleanVar(value=False)
        self.signed_var = tk.BooleanVar(value=False)
        self._build()
        self.root.after(100, self._pump)
        threading.Thread(target=self._poll_loop, daemon=True).start()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        w = self.win = tk.Toplevel(self.root)
        w.title("Function logger")
        w.geometry(self.app.settings.get("funclog_geom", "1240x620"))
        w.configure(bg=theme.c("bg"))
        w.protocol("WM_DELETE_WINDOW", self.close)
        f = ttk.Frame(w, padding=8)
        f.pack(fill="both", expand=True)

        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Label(top, text="Function").pack(side="left")
        e = ttk.Entry(top, textvariable=self.addr_var, width=34)
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda _e: self.on_start())
        self.start_btn = ttk.Button(top, text="Start logging", style="Accent.TButton", command=self.on_start)
        self.start_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.on_stop, state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        ttk.Label(top, textvariable=self.where_var, style="Muted.TLabel").pack(side="left", padx=8)

        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(6, 4))
        ttk.Label(bar, textvariable=self.stat_var, font=("Segoe UI", 10, "bold")).pack(side="left")
        for text, cmd in (("Export CSV…", self.on_export), ("Clear", self.on_clear)):
            ttk.Button(bar, text=text, style="Small.TButton", command=cmd).pack(side="right", padx=(4, 0))
        ttk.Checkbutton(bar, text="pause view", variable=self.pause_var).pack(side="right", padx=6)
        ttk.Checkbutton(bar, text="signed", variable=self.signed_var,
                        command=self._redraw).pack(side="right", padx=6)
        ttk.Checkbutton(bar, text="group by caller", variable=self.group_var,
                        command=self._redraw).pack(side="right", padx=6)

        pw = tk.PanedWindow(f, orient="horizontal", sashwidth=6, bd=0, bg=theme.c("bg"))
        pw.pack(fill="both", expand=True)
        left = ttk.Frame(pw)
        self.tree = ttk.Treeview(left, columns=COLS, show="headings", selectmode="browse")
        for col, text, wdt in (("n", "#", 52), ("t", "Time", 66), ("caller", "Called from", 150),
                               ("rdi", "rdi (1)", 92), ("rsi", "rsi (2)", 92), ("rdx", "rdx (3)", 84),
                               ("rcx", "rcx (4)", 84), ("r8", "r8 (5)", 76), ("r9", "r9 (6)", 76),
                               ("xmm0", "xmm0 f32", 72)):
            self.tree.heading(col, text=text, anchor="w")
            self.tree.column(col, width=wdt, minwidth=40, anchor="w", stretch=col == "caller")
        theme.stripe(self.tree)
        ys = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_detail())
        self.tree.bind("<Button-3>", self._menu)
        pw.add(left, stretch="always", minsize=600)

        right = ttk.Frame(pw)
        ttk.Label(right, text="Selected call", style="Title.TLabel").pack(anchor="w")
        self.detail = tk.Text(right, width=40, font=theme.mono(9), bg=theme.c("surface"), fg=theme.c("fg"),
                              relief="flat", wrap="none")
        self.detail.pack(fill="both", expand=True, pady=(4, 0))
        pw.add(right, minsize=260)
        ttk.Label(f, style="Muted.TLabel", wraplength=1040, justify="left",
                  text="The first instructions of the function are replaced by a jump to a small logger "
                       "that records each call and runs them itself, so the game is never stopped.  Arguments "
                       "follow the PS5 (System V) order: rdi, rsi, rdx, rcx, r8, r9, then the stack; float "
                       "arguments use xmm0-xmm3.  Stop puts the original bytes back.").pack(anchor="w", pady=(6, 0))

    # ------------------------------------------------------------------ plumbing
    def _post(self, fn) -> None:
        self._q.put(fn)

    def _pump(self) -> None:
        if self._closed:
            return
        try:
            for _ in range(50):
                self._q.get_nowait()()
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def _conn(self):
        main = self.app.client
        if not main.connected:
            raise RuntimeError("connect to the console first")
        if self.cli is None or not self.cli.connected:
            self.cli = main.clone()
            self.cli.timeout = 15.0
        return self.cli

    def _where(self, a: int) -> str:
        maps = getattr(self.app, "_maps_cache", None) or []
        try:
            from debugger_core import describe_addr      # noqa: PLC0415
            return describe_addr(maps, a, True) if maps else f"{a:X}"
        except Exception:
            return f"{a:X}"

    # ------------------------------------------------------------------ actions
    def on_start(self) -> None:
        if self.lg and self.lg.active:
            return
        try:
            addr = self.app.eval_full(self.addr_var.get())
            pid = self.app._pid()
        except Exception as exc:
            self.stat_var.set(f"error: {exc}")
            return
        dbg = getattr(self.app, "debugger", None)
        bps = dbg.bp_addrs() if dbg else ()
        self.stat_var.set("installing…")
        self.start_btn.configure(state="disabled")

        def work() -> None:
            try:
                cli = self._conn()
                try:
                    self.app._maps_cache = cli.maps(pid)
                except Exception:
                    pass
                lg = fl.FuncLogger(cli, pid, addr)
                lg.start(bps)
                self.lg = lg
                self._rate = [(time.monotonic(), 0)]

                def ok() -> None:
                    self.where_var.set(self._where(addr))
                    self.stop_btn.configure(state="normal")
                    self.stat_var.set("logging - waiting for the first call…")
                    self.app.log_line(f"function logger: hooked 0x{addr:X} ({len(lg.orig)} bytes moved to "
                                      f"0x{lg.cave:X}, ring 0x{lg.ring:X})" + (f"  [{'; '.join(lg.notes)}]"
                                                                               if lg.notes else ""))
                self._post(ok)
            except Exception as exc:
                self._post(lambda e=exc: (self.stat_var.set(f"error: {e}"), self.start_btn.configure(state="normal")))
        threading.Thread(target=work, daemon=True).start()

    def on_stop(self) -> None:
        lg = self.lg
        if not lg:
            return

        def work() -> None:
            try:
                tail = lg.poll()
                lg.stop()
                self._post(lambda: (self._add(tail), self._after_stop()))
            except Exception as exc:
                self._post(lambda e=exc: self.stat_var.set(f"error while stopping: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def _after_stop(self) -> None:
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        lg = self.lg
        self.stat_var.set(f"stopped - {lg.seen:,} call(s) logged" + (f", {lg.lost:,} missed" if lg.lost else ""))
        self.app.log_line(f"function logger: removed hook at 0x{lg.addr:X}")

    def on_clear(self) -> None:
        self.calls.clear()
        self.groups.clear()
        self.tree.delete(*self.tree.get_children())
        self.detail.delete("1.0", "end")

    def on_export(self) -> None:
        if not self.calls:
            return
        path = filedialog.asksaveasfilename(parent=self.win, defaultextension=".csv",
                                            initialfile=time.strftime("calls_%H%M%S.csv"),
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            wr = csv.writer(fh)
            wr.writerow(["n", "time", "return", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "rbx", "rbp", "rsp",
                         "xmm0_f32", "xmm1_f32", "xmm0_f64", "stack1", "stack2", "stack3", "stack4", "stack5"])
            for k in self.calls:
                r = k.regs
                wr.writerow([k.index, time.strftime("%H:%M:%S", time.localtime(k.time)), f"0x{k.ret:X}",
                             *(f"0x{r[x]:X}" for x in ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "rbx", "rbp")),
                             f"0x{k.rsp:X}", k.xmm_f32(0), k.xmm_f32(1), k.xmm_f64(0),
                             *(f"0x{s:X}" for s in k.stack)])
        self.app.log_line(f"function logger: exported {len(self.calls):,} call(s) to {path}")

    # ------------------------------------------------------------------ polling
    def _poll_loop(self) -> None:
        while not self._closed:
            time.sleep(0.25)
            lg = self.lg
            if not lg or not lg.active:
                continue
            try:
                new = lg.poll()
            except Exception as exc:
                self._post(lambda e=exc: self.stat_var.set(f"read error: {e}"))
                time.sleep(1.0)
                continue
            if new:
                self._post(lambda n=new: self._add(n))
            self._post(self._stats)

    def _stats(self) -> None:
        lg = self.lg
        if not lg or not lg.active:
            return
        now = time.monotonic()
        self._rate.append((now, lg.seen))
        self._rate = [x for x in self._rate if now - x[0] <= 3.0] or [(now, lg.seen)]
        t0, n0 = self._rate[0]
        rate = (lg.seen - n0) / (now - t0) if now > t0 else 0.0
        self.stat_var.set(f"logging - {lg.seen:,} call(s)  ·  {rate:,.0f}/s" +
                          (f"  ·  {lg.lost:,} missed (too fast to keep every call)" if lg.lost else ""))

    def _fmt(self, v: int) -> str:
        if self.signed_var.get() and v >= 1 << 63:
            return str(v - (1 << 64))
        return f"{v:X}"

    def _add(self, new: list) -> None:
        if not new:
            return
        self.calls.extend(new)
        if len(self.calls) > 50000:
            del self.calls[: len(self.calls) - 50000]
        for k in new:
            g = self.groups.setdefault(k.ret, [0, k])
            g[0] += 1
            g[1] = k
        if self.pause_var.get():
            return
        if self.group_var.get():
            self._redraw()
            return
        for k in new:
            self._insert_call(k)
        kids = self.tree.get_children()
        if len(kids) > MAX_ROWS:
            self.tree.delete(*kids[: len(kids) - MAX_ROWS])
        self.tree.yview_moveto(1.0)

    def _row(self, k: fl.Call, first: str) -> tuple:
        r = k.regs
        return (first, time.strftime("%H:%M:%S", time.localtime(k.time)), self._where(k.ret),
                *(self._fmt(r[x]) for x in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")), f"{k.xmm_f32(0):.6g}")

    def _insert_call(self, k: fl.Call) -> None:
        iid = f"c{k.index}"
        if not self.tree.exists(iid):
            self.tree.insert("", "end", iid=iid, values=self._row(k, str(k.index + 1)))

    def _redraw(self) -> None:
        self.tree.delete(*self.tree.get_children())
        if self.group_var.get():
            for ret, (cnt, k) in sorted(self.groups.items(), key=lambda x: -x[1][0]):
                self.tree.insert("", "end", iid=f"g{ret:x}", values=self._row(k, f"{cnt:,}×"))
            self.tree.heading("n", text="Calls")
        else:
            self.tree.heading("n", text="#")
            for k in self.calls[-MAX_ROWS:]:
                self._insert_call(k)

    def _selected(self) -> Optional[fl.Call]:
        sel = self.tree.selection()
        if not sel:
            return None
        iid = sel[0]
        if iid.startswith("g"):
            g = self.groups.get(int(iid[1:], 16))
            return g[1] if g else None
        idx = int(iid[1:])
        return next((k for k in reversed(self.calls) if k.index == idx), None)

    def _show_detail(self) -> None:
        k = self._selected()
        self.detail.delete("1.0", "end")
        if not k:
            return
        r = k.regs
        lines = [f"call #{k.index + 1}", f"from  {self._where(k.ret)}", f"rsp   {k.rsp:016X}", ""]
        for i, name in enumerate(fl.ARG_REGS):
            lines.append(f"arg{i + 1} {name:<4}{r[name]:016X}  {self._fmt(r[name]) if self.signed_var.get() else ''}")
        for i, s in enumerate(k.stack):
            lines.append(f"arg{i + 7} [rsp+{8 * (i + 1):X}] {s:016X}")
        lines.append("")
        for name in ("rax", "rbx", "rbp", "r10", "r11", "r12", "r13", "r14", "r15"):
            lines.append(f"{name:<6}{r[name]:016X}")
        lines.append(f"rflags {r['rflags']:08X}")
        lines.append("")
        for i in range(4):
            f4 = struct.unpack("<4f", k.xmm[i])
            d2 = struct.unpack("<2d", k.xmm[i])
            lines.append(f"xmm{i}  f32 {', '.join(f'{x:.6g}' for x in f4)}")
            lines.append(f"      f64 {d2[0]:.10g}, {d2[1]:.10g}")
        self.detail.insert("1.0", "\n".join(lines))

    def _menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
        k = self._selected()
        if not k:
            return
        m = tk.Menu(self.win, tearoff=0)
        for name in fl.ARG_REGS:
            v = k.regs[name]
            m.add_command(label=f"View {name} (0x{v:X}) in hex editor",
                          command=lambda v=v: self.app._hex_goto_value(v, 0x100))
        m.add_separator()
        m.add_command(label="Show caller in Disassembler", command=lambda: self.app.show_in_disassembler(k.ret))
        m.add_command(label="Copy this call", command=lambda: (
            self.root.clipboard_clear(), self.root.clipboard_append(self.detail.get("1.0", "end-1c"))))
        m.tk_popup(event.x_root, event.y_root)

    def close(self) -> None:
        self._closed = True
        try:
            self.app.settings["funclog_geom"] = self.win.geometry()
        except tk.TclError:
            pass
        lg, cli = self.lg, self.cli

        def work() -> None:
            try:
                if lg and lg.active:
                    lg.stop()
                    self.app.root.after(0, lambda: self.app.log_line(
                        f"function logger: removed hook at 0x{lg.addr:X}"))
            except Exception:
                pass
            time.sleep(2.5)             # the delayed free uses this connection
            if cli is not None:
                cli.close()
        threading.Thread(target=work, daemon=True).start()
        self.win.destroy()
