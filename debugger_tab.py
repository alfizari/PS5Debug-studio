"""Debugger tab - attach to the game through ps5debug-NG, set breakpoints /
watchpoints, run, pause, step into / over / out, and inspect registers, the
call stack and the raw stack.

How it works (see PROTOCOL.md of ps5debug-NG):
  * Commands go over the normal connection (port 744).
  * Stop events (breakpoint hit, single-step, signal, watchpoint) are pushed by
    the console to TCP 755 on this PC, so the tab starts listening on 755
    before it attaches.
  * Software breakpoints are int3 (0xCC) patched into game memory, up to 30
    slots (one is reserved here for the temporary breakpoint used by Step
    Over / Step Out / Run to cursor).  Hardware watchpoints use DR0-DR3.
"""

from __future__ import annotations

import queue
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Callable, Optional

import disasm
import unwind
from debugger_core import (
    REG_DISPLAY, REG_INFO, WATCH_LEN, WATCH_TYPE, InterruptListener, StopEvent,
    VEC_FORMATS, describe_addr, flags_text, fpu_ok, is_exec, label_for, mxcsr_get, mxcsr_set, mxcsr_text,
    parse_regs, patch_reg, vec_get, vec_hex, vec_parse, vec_set, vec_text,
)
from disasm import K_CALL, Insn
from disasm_view import DisasmView
from ps5debug_client import ProtocolError
import theme  # noqa: E402


Bp = dict  # {"kind": "bp"|"wp", "slot", "addr", "enabled", "hits", "applied", "orig", "len", "wtype"}


class DebuggerTab:
    RUN_SLOTS = (28, 29)        # temporary breakpoint of step over / step out / run to cursor (alternate)
    MAX_BP = 28                 # user slots 0..27
    MAX_WP = 4

    def __init__(self, parent: ttk.Frame, app) -> None:
        self.app = app
        self.client = app.client
        self.parent = parent
        self.listener: Optional[InterruptListener] = None
        self.attached = False
        self.running = False
        self.stopped = False
        self.pid = 0
        self.evt: Optional[StopEvent] = None
        self.regs: dict[str, int] = {}          # event thread (used for stepping)
        self.regs_blob = b""
        self.prev_regs: dict[str, int] = {}
        self.disp_lwp = 0                       # thread whose registers are shown
        self.disp_regs: dict[str, int] = {}
        self.disp_blob = b""
        self.disp_fpu = b""                     # xsave image of the shown thread (XMM / YMM / MXCSR)
        self.prev_fpu = b""
        self._real_fpu = b""                    # live FPU state of the stopped thread (GETFPREGS)
        self.xmm_fmt = tk.StringVar(value="Float x4")
        self.xmm_ymm = tk.BooleanVar(value=False)
        self.bps: list[Bp] = []
        self._temp: Optional[dict] = None
        self._maps: list = []
        self._frames: list[dict] = []
        self._thread_names: dict[int, str] = {}
        self._notes: list[str] = []
        self.view_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Detached")
        self.rel_addr = tk.BooleanVar(value=False)       # True: module+offset instead of absolute addresses
        self.step_mode = tk.StringVar(value="native")
        self._mode = "native"                            # read by worker threads (Tk vars are main-thread only)
        # Console rules this tab follows (ps5debug-NG debug.c):
        #  * switching a software breakpoint OFF makes the console PT_CONTINUE the game, so while the game is
        #    stopped such a disarm is queued here and only done together with the next resume;
        #  * on a breakpoint hit the console steps over the breakpointed instruction BEFORE it reports the stop.
        self._to_disarm: list[Bp] = []
        self._prestepped = False                         # True: the thread is already past the instruction at RIP
        self._real_blob = b""                            # live registers of the stopped thread (GETREGS)
        self._stack_bytes = b""
        # speed: a stop first shows registers + code (2-3 round trips); the other panels load afterwards,
        # and only the visible one.  Anything newer (a step, a continue) cancels the leftover loading.
        self._stop_gen = 0
        self._tab_now = "Call stack"                     # visible lower tab (plain str: read by worker threads)
        self._stale: set[str] = set()                    # lower panels not loaded for the current stop
        self._maps_time = 0.0
        self._code_cache: list[Insn] = []                # last disassembly at RIP (reused while stepping)
        self._code_key: tuple = ()
        self._bulk_ok = True                             # console accepts the bulk read (CC03)
        self._fcode: dict[int, tuple] = {}               # code address -> (func start, entry bytes, bytes here, 8 before)
        self._rip_func: Optional[int] = None
        self.step_mode.trace_add("write", lambda *_: setattr(self, "_mode", self.step_mode.get()))
        self.rel_addr.trace_add("write", lambda *_: self._relabel())
        self._build(parent)
        self.xmm_fmt.trace_add("write", lambda *_: self._fill_xmm())
        self.xmm_ymm.trace_add("write", lambda *_: self._fill_xmm())
        self._update_buttons()
        self._bind_keys()

    # ================================================================ UI
    def _build(self, parent: ttk.Frame) -> None:
        style = ttk.Style(parent)
        style.configure("Dbg.Treeview", font=("Consolas", 9), rowheight=17)

        bar = ttk.Frame(parent, padding=(8, 8, 8, 2))
        bar.pack(fill="x")
        self.btn = {}

        def add(key: str, text: str, cmd: Callable[[], None], pad: tuple = (2, 2)) -> None:
            b = ttk.Button(bar, text=text, command=cmd)
            b.pack(side="left", padx=pad)
            self.btn[key] = b

        add("attach", "Attach", self.on_attach)
        add("detach", "Detach", self.on_detach, (2, 14))
        add("pause", "Pause  (F6)", self.on_pause)
        add("cont", "Continue  (F5)", self.on_continue)
        add("into", "Step into  (F7)", self.on_step_into)
        add("over", "Step over  (F8)", self.on_step_over)
        add("out", "Step out  (Shift+F8)", self.on_step_out)
        add("runto", "Run to cursor  (F4)", self.on_run_to_selected)
        bar2 = ttk.Frame(parent, padding=(8, 0, 8, 0))
        bar2.pack(fill="x")
        ttk.Label(bar2, text="Step method").pack(side="left")
        ttk.Combobox(bar2, textvariable=self.step_mode, state="readonly", width=15,
                     values=("native", "native thread")).pack(side="left", padx=4)
        ttk.Label(bar2, foreground=theme.c("muted"),
                  text="native = step the process (as the reference client does);  native thread = step only the stopped thread"
                  ).pack(side="left", padx=4)
        ttk.Checkbutton(bar2, text="module+offset instead of absolute addresses",
                        variable=self.rel_addr).pack(side="left", padx=14)
        ttk.Label(parent, textvariable=self.status_var, font=("Segoe UI", 10, "bold"),
                  padding=(10, 2)).pack(anchor="w")

        body = tk.PanedWindow(parent, orient="horizontal", sashwidth=6, sashrelief="raised", bd=0)
        body.pack(fill="both", expand=True, padx=6, pady=(2, 4))
        left = ttk.Frame(body)
        right = tk.PanedWindow(body, orient="vertical", sashwidth=6, sashrelief="raised", bd=0)
        body.add(left, minsize=520, stretch="always")
        body.add(right, minsize=400, stretch="always")

        # ---- left: code + breakpoints
        gb = ttk.Frame(left)
        gb.pack(fill="x", pady=(0, 3))
        ttk.Label(gb, text="View address").pack(side="left")
        e = ttk.Entry(gb, textvariable=self.view_var, width=34)
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda ev: self.on_view_go())
        ttk.Button(gb, text="Go", width=5, command=self.on_view_go).pack(side="left", padx=2)
        ttk.Button(gb, text="Go to RIP", command=self.on_view_rip).pack(side="left", padx=2)

        self.view = DisasmView(
            left, on_follow=self._follow, menu_items=self._menu, on_toggle_bp=lambda i: self.toggle_bp(i.addr),
            height=16,
        )
        self.view.pack(fill="both", expand=True)

        bpf = ttk.LabelFrame(left, text="Breakpoints / watchpoints", padding=4)
        bpf.pack(fill="x", pady=(4, 0))
        self.bp_tree = ttk.Treeview(
            bpf, columns=("slot", "type", "addr", "where", "on", "hits"), show="headings", height=5,
            style="Dbg.Treeview", selectmode="browse",
        )
        for col, title, w in (("slot", "#", 34), ("type", "Type", 90), ("addr", "Address", 140),
                              ("where", "Location", 190), ("on", "On", 70), ("hits", "Hits", 50)):
            self.bp_tree.heading(col, text=title)
            self.bp_tree.column(col, width=w, minwidth=30, stretch=(col == "where"))
        bps = ttk.Scrollbar(bpf, orient="vertical", command=self.bp_tree.yview)
        self.bp_tree.configure(yscrollcommand=bps.set)
        self.bp_tree.grid(row=0, column=0, sticky="nsew")
        bps.grid(row=0, column=1, sticky="ns")
        bpf.grid_columnconfigure(0, weight=1)
        self.bp_tree.bind("<Double-1>", lambda ev: self.on_bp_toggle_enabled())
        bb = ttk.Frame(bpf)
        bb.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Button(bb, text="Add breakpoint...", command=self.on_add_bp).pack(side="left", padx=2)
        ttk.Button(bb, text="Add watchpoint...", command=self.on_add_wp).pack(side="left", padx=2)
        ttk.Button(bb, text="Enable / disable", command=self.on_bp_toggle_enabled).pack(side="left", padx=2)
        ttk.Button(bb, text="Remove", command=self.on_bp_remove).pack(side="left", padx=2)
        ttk.Button(bb, text="Remove all", command=self.on_bp_remove_all).pack(side="left", padx=2)

        # ---- right: registers + notebook
        regf = ttk.LabelFrame(right, text="Registers  (double-click: edit   right-click: copy / view in hex editor)",
                              padding=4)
        self.reg_tree = ttk.Treeview(
            regf, columns=("reg", "value", "info"), show="headings", height=12, style="Dbg.Treeview",
        )
        for col, title, w, st in (("reg", "Reg", 62, False), ("value", "Value", 150, False),
                                  ("info", "Info", 220, True)):
            self.reg_tree.heading(col, text=title)
            self.reg_tree.column(col, width=w, minwidth=40, stretch=st)
        rs = ttk.Scrollbar(regf, orient="vertical", command=self.reg_tree.yview)
        self.reg_tree.configure(yscrollcommand=rs.set)
        self.reg_tree.pack(side="left", fill="both", expand=True)
        rs.pack(side="right", fill="y")
        self.reg_tree.tag_configure("chg", foreground=theme.c("danger"))
        for name in REG_DISPLAY:
            self.reg_tree.insert("", "end", iid=name, values=(name.upper(), "", ""))
        self.reg_tree.bind("<Double-1>", self.on_reg_edit)
        self.reg_tree.bind("<Button-3>", self._reg_menu)
        self.reg_tree.bind("<Control-c>", lambda e: self._copy_reg_key())
        right.add(regf, minsize=150, stretch="always")

        nb = ttk.Notebook(right)
        right.add(nb, minsize=150, stretch="always")
        self._nb = nb
        nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        stf = ttk.Frame(nb, padding=2)
        nb.add(stf, text="Call stack")
        self.frame_tree = ttk.Treeview(
            stf, columns=("n", "ret", "where", "func", "call"), show="headings", height=8, style="Dbg.Treeview",
            selectmode="browse",
        )
        for col, title, w, st in (("n", "#", 30, False), ("ret", "Returns to", 130, False),
                                  ("where", "Location", 150, True), ("func", "Function (est.)", 170, True),
                                  ("call", "Call site", 200, True)):
            self.frame_tree.heading(col, text=title)
            self.frame_tree.column(col, width=w, minwidth=26, stretch=st)
        fs = ttk.Scrollbar(stf, orient="vertical", command=self.frame_tree.yview)
        self.frame_tree.configure(yscrollcommand=fs.set)
        self.frame_tree.pack(side="left", fill="both", expand=True)
        fs.pack(side="right", fill="y")
        self.frame_tree.bind("<Double-1>", self.on_frame_open)
        self.frame_tree.bind("<Button-3>", self._frame_menu)

        self._build_xmm(nb)

        skf = ttk.Frame(nb, padding=2)
        nb.add(skf, text="Stack (RSP)")
        self.stack_tree = ttk.Treeview(
            skf, columns=("addr", "value", "info"), show="headings", height=8, style="Dbg.Treeview",
        )
        for col, title, w, st in (("addr", "Address", 130, False), ("value", "Value", 130, False),
                                  ("info", "Info", 210, True)):
            self.stack_tree.heading(col, text=title)
            self.stack_tree.column(col, width=w, minwidth=40, stretch=st)
        ss = ttk.Scrollbar(skf, orient="vertical", command=self.stack_tree.yview)
        self.stack_tree.configure(yscrollcommand=ss.set)
        self.stack_tree.pack(side="left", fill="both", expand=True)
        ss.pack(side="right", fill="y")
        self.stack_tree.tag_configure("ret", foreground=theme.c("call"))
        self.stack_tree.bind("<Double-1>", self.on_stack_open)
        self.stack_tree.bind("<Button-3>", self._stack_menu)
        self.stack_tree.bind("<Control-c>", lambda e: self._copy_stack_key())

        thf = ttk.Frame(nb, padding=2)
        nb.add(thf, text="Threads")
        self.thr_tree = ttk.Treeview(
            thf, columns=("lwp", "name", "state"), show="headings", height=8, style="Dbg.Treeview",
            selectmode="browse",
        )
        for col, title, w, st in (("lwp", "LWP", 80, False), ("name", "Name", 200, True),
                                  ("state", "", 90, False)):
            self.thr_tree.heading(col, text=title)
            self.thr_tree.column(col, width=w, minwidth=30, stretch=st)
        self.thr_tree.pack(fill="both", expand=True)
        self.thr_tree.bind("<Double-1>", lambda ev: self.on_thread_show())
        tb = ttk.Frame(thf)
        tb.pack(fill="x", pady=(3, 0))
        ttk.Button(tb, text="Show registers", command=self.on_thread_show).pack(side="left", padx=2)
        ttk.Button(tb, text="Suspend", command=lambda: self.on_thread_ctl(True)).pack(side="left", padx=2)
        ttk.Button(tb, text="Resume", command=lambda: self.on_thread_ctl(False)).pack(side="left", padx=2)

        ttk.Label(
            parent, foreground=theme.c("muted"),
            text="F5 continue   F6 pause   F7 step into   F8 step over   Shift+F8 step out   F4 run to cursor   "
                 "F9 breakpoint on the selected line.   Debug events arrive on TCP port 755.",
        ).pack(anchor="w", padx=10, pady=(0, 4))

    def _build_xmm(self, nb: ttk.Notebook) -> None:
        xf = ttk.Frame(nb, padding=2)
        nb.add(xf, text="XMM / FPU")
        top = ttk.Frame(xf)
        top.pack(fill="x", pady=(0, 3))
        ttk.Label(top, text="Show as").pack(side="left")
        ttk.Combobox(top, textvariable=self.xmm_fmt, values=list(VEC_FORMATS), state="readonly",
                     width=15).pack(side="left", padx=4)
        ttk.Checkbutton(top, text="YMM (256-bit)", variable=self.xmm_ymm).pack(side="left", padx=8)
        ttk.Label(top, foreground=theme.c("muted"),
                  text="double-click: edit   right-click: copy").pack(side="right")
        self.xmm_tree = ttk.Treeview(
            xf, columns=("reg", "value", "hex"), show="headings", height=8, style="Dbg.Treeview",
            selectmode="browse",
        )
        for col, title, w, st in (("reg", "Reg", 62, False), ("value", "Value (lane 0 first)", 260, True),
                                  ("hex", "Hex (high \u2192 low)", 300, True)):
            self.xmm_tree.heading(col, text=title)
            self.xmm_tree.column(col, width=w, minwidth=40, stretch=st)
        xs = ttk.Scrollbar(xf, orient="vertical", command=self.xmm_tree.yview)
        self.xmm_tree.configure(yscrollcommand=xs.set)
        self.xmm_tree.pack(side="left", fill="both", expand=True)
        xs.pack(side="right", fill="y")
        self.xmm_tree.tag_configure("chg", foreground=theme.c("danger"))
        for i in range(16):
            self.xmm_tree.insert("", "end", iid=f"x{i}", values=(f"XMM{i}", "", ""))
        self.xmm_tree.insert("", "end", iid="mxcsr", values=("MXCSR", "", ""))
        self.xmm_tree.bind("<Double-1>", lambda ev: self._edit_xmm(self.xmm_tree.identify_row(ev.y)))
        self.xmm_tree.bind("<Button-3>", self._xmm_menu)
        self.xmm_tree.bind("<Control-c>", lambda e: self._copy_xmm_key())

    def _bind_keys(self) -> None:
        root = self.app.root

        def guard(fn: Callable[[], None]) -> Callable:
            def h(_e=None):
                nb = getattr(self.app, "notebook", None)
                if nb is not None and str(nb.select()) == str(self.parent):
                    fn()
                    return "break"
            return h

        for key, fn in (("<F5>", self.on_continue), ("<F6>", self.on_pause), ("<F7>", self.on_step_into),
                        ("<F8>", self.on_step_over), ("<Shift-F8>", self.on_step_out),
                        ("<F4>", self.on_run_to_selected)):
            root.bind(key, guard(fn), add="+")

    def _update_buttons(self) -> None:
        def st(key: str, on: bool) -> None:
            self.btn[key].configure(state="normal" if on else "disabled")

        st("attach", not self.attached)
        st("detach", self.attached)
        st("pause", self.attached and self.running)
        for k in ("cont", "into", "over", "out", "runto"):
            st(k, self.attached and self.stopped)

    def _set_status(self) -> None:
        if not self.attached:
            self.status_var.set("Detached")
        elif self.running:
            self.status_var.set(f"Attached to pid {self.pid} - RUNNING")
        elif self.stopped and self.evt:
            rip = self.regs.get("rip", 0)
            note = ("   " + "; ".join(self._notes)) if self._notes else ""
            self.status_var.set(
                f"STOPPED   RIP = 0x{rip:X}   thread {self.evt.lwpid} {self.evt.tdname}   {self.evt.signame}{note}"
            )
        else:
            self.status_var.set(f"Attached to pid {self.pid}")
        self._update_buttons()

    # ====================================================== public hooks
    def rip_for_marks(self) -> Optional[int]:
        return self.regs.get("rip") if (self.attached and self.stopped) else None

    def bp_addrs(self) -> set[int]:
        return {b["addr"] for b in self.bps if b["kind"] == "bp" and b["enabled"]}

    def bp_overrides(self) -> dict[int, int]:
        """addr -> original byte for breakpoints currently patched into memory."""
        return {b["addr"]: b["orig"] for b in self.bps
                if b["kind"] == "bp" and b["applied"] and b["enabled"] and b["orig"] is not None}

    def _when_idle(self, fn: Callable[[], None]) -> None:
        if self.app._busy:
            self.app.root.after(60, lambda: self._when_idle(fn))
        else:
            fn()

    def _need_stopped(self) -> bool:
        if not self.attached:
            self.app.log_line("debugger: attach first")
            return False
        if not self.stopped:
            self.app.log_line("debugger: the game is running - press Pause (F6) first")
            return False
        self._stop_gen += 1                     # a new run-control action: drop leftover panel loading
        return True

    # ============================================== attach / detach
    def on_attach(self) -> None:
        if self.attached:
            return
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return
        root = self.app.root
        try:
            if self.listener is None:
                self.listener = InterruptListener(
                    on_event=lambda e: root.after(0, lambda: self._on_stop(e)),
                    on_log=lambda m: root.after(0, lambda: self.app.log_line(m)),
                    on_closed=lambda: root.after(0, self._channel_lost),
                )
            self.listener.start()
        except RuntimeError as exc:
            self.app._fail(exc)
            return

        def work() -> None:
            self.client.debug_attach(pid)
            self.pid = pid
            self.attached = True
            self.running = True
            self.stopped = False
            for b in self.bps:
                if b["enabled"]:
                    try:
                        self._apply(b)
                    except Exception as exc:
                        root.after(0, lambda e=exc, a=b["addr"]: self.app.log_line(
                            f"could not set breakpoint at 0x{a:X}: {e}"))
            self._fcode.clear()
            try:
                self._maps = self.client.maps(pid)
                self.app._maps_cache = self._maps
                self._maps_time = time.monotonic()
            except Exception:
                pass
            self._code_cache = []
            root.after(0, self._after_attach)

        self.app._run_bg(work, "Attaching debugger...")

    def _after_attach(self) -> None:
        self.app.log_line(f"debugger attached to pid {self.pid}")
        self._set_status()
        self._fill_bps()
        self._refresh_marks()

    def on_detach(self) -> None:
        if not self.attached:
            return

        def work() -> None:
            try:
                self.client.debug_detach()
            finally:
                self._reset_state()
            self.app.root.after(0, self._after_detach)

        self.app._run_bg(work, "Detaching...")

    def _reset_state(self) -> None:
        self.attached = False
        self.running = False
        self.stopped = False
        self._temp = None
        self._to_disarm = []
        self._prestepped = False
        self._real_blob = b""
        self._real_fpu = b""
        for b in self.bps:
            b["applied"] = False
        if self.listener:
            self.listener.stop()
            self.listener = None

    def _channel_lost(self) -> None:
        """The console closed the debug channel: the session is over - reflect that."""
        if not self.attached:
            return
        self.app.log_line("debugger: the console ended the debug session. If commands now fail with a "
                          "connection error, press Disconnect and Connect again.")
        self._reset_state()
        self._after_detach()

    def _after_detach(self) -> None:
        self.app.log_line("debugger detached")
        self._set_status()
        self._fill_bps()
        self._refresh_marks()

    # =================================================== breakpoints
    def _bp_at(self, addr: int) -> Optional[Bp]:
        for b in self.bps:
            if b["kind"] == "bp" and b["applied"] and b["enabled"] and b["addr"] == addr:
                return b
        return None

    def _bp_by_addr(self, addr: int) -> Optional[Bp]:
        for b in self.bps:
            if b["kind"] == "bp" and b["addr"] == addr:
                return b
        return None

    def _free_slot(self, kind: str) -> Optional[int]:
        used = {b["slot"] for b in self.bps if b["kind"] == kind}
        used |= {b["slot"] for b in self._to_disarm if b["kind"] == kind}     # still armed on the console
        for i in range(self.MAX_BP if kind == "bp" else self.MAX_WP):
            if i not in used:
                return i
        return None

    def _apply(self, b: Bp) -> None:
        """Push one breakpoint/watchpoint to the console (worker thread)."""
        if b["kind"] == "bp":
            self.client.debug_set_breakpoint(b["slot"], b["enabled"], b["addr"])
        else:
            self.client.debug_set_watchpoint(
                b["slot"], b["enabled"], WATCH_LEN[b["len"]], WATCH_TYPE[b["wtype"]], b["addr"])
        b["applied"] = b["enabled"]

    def _set_armed(self, b: Bp, want: bool) -> None:
        """Arm / disarm one breakpoint (worker thread).  Disarming a software breakpoint makes the console
        resume the game, so while the game is stopped the disarm is only queued (see _flush_disarm)."""
        if b["kind"] != "bp":
            b["enabled"] = want
            self._apply(b)
            return
        if want:
            b["enabled"] = True
            if b in self._to_disarm:            # never actually disarmed: just cancel the queued disarm
                self._to_disarm.remove(b)
            elif not b["applied"]:
                self._apply(b)
        else:
            b["enabled"] = False
            if not b["applied"]:
                return
            if self.stopped:
                if b not in self._to_disarm:
                    self._to_disarm.append(b)
            else:
                self._apply(b)

    def _flush_disarm(self) -> None:
        """Do the queued disarms.  Only called right before the game is resumed anyway."""
        pend, self._to_disarm = self._to_disarm, []
        for b in pend:
            b["enabled"] = False
            try:
                self._apply(b)
            except Exception as exc:
                self.app.root.after(0, lambda e=exc, a=b["addr"]: self.app.log_line(
                    f"debugger: could not disarm 0x{a:X}: {e}"))

    def toggle_bp(self, addr: int) -> None:
        existing = self._bp_by_addr(addr)
        if existing:
            self._remove([existing])
        else:
            self.add_bp(addr)

    def add_bp(self, addr: int) -> None:
        slot = self._free_slot("bp")
        if slot is None:
            self.app.log_line(f"debugger: all {self.MAX_BP} breakpoint slots are in use")
            return
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return

        def work() -> None:
            pending = next((p for p in self._to_disarm if p["kind"] == "bp" and p["addr"] == addr), None)
            if pending is not None:             # removed a moment ago while stopped: still armed, just keep it
                self._to_disarm.remove(pending)
                pending["enabled"], pending["hits"] = True, 0
                if pending not in self.bps:
                    self.bps.append(pending)
                self.app.root.after(0, self._bps_changed)
                return
            try:
                orig: Optional[int] = self.client.read(pid, addr, 1)[0]
            except Exception as exc:
                raise RuntimeError(f"cannot read 0x{addr:X} to place a breakpoint: {exc}") from exc
            if orig == 0xCC:
                orig = None
                self.app.root.after(0, lambda: self.app.log_line(
                    f"warning: 0x{addr:X} already holds 0xCC; the original byte is unknown"))
            b: Bp = {"kind": "bp", "slot": slot, "addr": addr, "enabled": True, "hits": 0,
                     "applied": False, "orig": orig}
            if self.attached:
                self._apply(b)
            self.bps.append(b)
            self.app.root.after(0, self._bps_changed)

        self.app._run_bg(work, "Setting breakpoint...")

    def _remove(self, items: list[Bp]) -> None:
        def work() -> None:
            for b in items:
                if b["applied"] and self.attached:
                    try:
                        self._set_armed(b, False)
                    except Exception as exc:
                        self.app.root.after(0, lambda e=exc: self.app.log_line(f"remove failed: {e}"))
                if b in self.bps:
                    self.bps.remove(b)
            self.app.root.after(0, self._bps_changed)

        self.app._run_bg(work, "Removing breakpoint...")

    def _selected_bp(self) -> Optional[Bp]:
        sel = self.bp_tree.selection()
        if not sel:
            return None
        idx = int(sel[0])
        return self.bps[idx] if idx < len(self.bps) else None

    BP_TYPES = (
        ("Software (int3)", None),
        ("Hardware - execute", "exec"),
        ("Hardware - write only (WRONLY)", "write"),
        ("Hardware - read / write (RDWR)", "read/write"),
    )
    BP_HELP = {
        None: "Patches 0xCC at the address. Unlimited (28 slots); code only. The game sees the changed byte.",
        "exec": "CPU debug register, no memory change - works in code that checks itself. Max 4 hardware slots.",
        "write": "Stops right AFTER an instruction writes the watched bytes (shows who changes a value).",
        "read/write": "Stops right AFTER an instruction reads or writes the watched bytes.",
    }

    def on_add_bp(self, addr: Optional[int] = None, kind: Optional[str] = None) -> None:
        self.open_bp_dialog(addr, kind)

    def on_add_wp(self) -> None:
        self.open_bp_dialog(None, "write")

    def open_bp_dialog(self, addr: Optional[int] = None, kind: Optional[str] = None) -> None:
        """One dialog for every breakpoint type: software int3 or hardware execute / write / read-write."""
        win = tk.Toplevel(self.app.root)
        win.title("Add breakpoint")
        win.transient(self.app.root)
        win.resizable(False, False)
        f = ttk.Frame(win, padding=14)
        f.pack(fill="both", expand=True)
        labels = [lbl for lbl, _k in self.BP_TYPES]
        start = next((lbl for lbl, k in self.BP_TYPES if k == kind), labels[0])
        addr_v = tk.StringVar(value=f"0x{addr:X}" if addr is not None else "")
        type_v = tk.StringVar(value=start)
        len_v = tk.StringVar(value="4")
        help_v = tk.StringVar()

        ttk.Label(f, text="Address").grid(row=0, column=0, sticky="w")
        e = ttk.Entry(f, textvariable=addr_v, width=36)
        e.grid(row=0, column=1, sticky="we", padx=6, pady=3)
        ttk.Label(f, text="Type").grid(row=1, column=0, sticky="w")
        ttk.Combobox(f, textvariable=type_v, values=labels, state="readonly", width=34).grid(
            row=1, column=1, sticky="we", padx=6, pady=3)
        ttk.Label(f, text="Size (bytes)").grid(row=2, column=0, sticky="w")
        size_cb = ttk.Combobox(f, textvariable=len_v, values=("1", "2", "4", "8"), width=6, state="readonly")
        size_cb.grid(row=2, column=1, sticky="w", padx=6, pady=3)
        ttk.Label(f, textvariable=help_v, style="Muted.TLabel", wraplength=380, justify="left").grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        hw_used = sum(1 for b in self.bps if b["kind"] == "wp")
        ttk.Label(f, text=f"Hardware slots in use: {hw_used} / {self.MAX_WP}", style="Muted.TLabel").grid(
            row=4, column=0, columnspan=2, sticky="w")

        def sync(*_a) -> None:
            k = dict(self.BP_TYPES)[type_v.get()]
            help_v.set(self.BP_HELP[k])
            if k in (None, "exec"):
                len_v.set("1")
                size_cb.configure(state="disabled")
            else:
                size_cb.configure(state="readonly")
                if len_v.get() == "1" and addr is None:
                    len_v.set("4")
        type_v.trace_add("write", sync)
        sync()

        def ok() -> None:
            try:
                a = self.app.eval_full(addr_v.get())
            except Exception as exc:
                messagebox.showerror("Breakpoint", str(exc), parent=win)
                return
            k = dict(self.BP_TYPES)[type_v.get()]
            size = int(len_v.get())
            if k in ("write", "read/write") and a % size:
                if not messagebox.askyesno(
                        "Breakpoint", f"0x{a:X} is not {size}-byte aligned; the CPU watches the aligned "
                                      f"block 0x{a & ~(size - 1):X}..+{size}. Continue?", parent=win):
                    return
            if k is not None and self._free_slot("wp") is None:
                messagebox.showerror("Breakpoint", "All 4 hardware slots are in use - remove one first.", parent=win)
                return
            win.destroy()
            if k is None:
                self.add_bp(a)
            else:
                self.add_watchpoint(a, 1 if k == "exec" else size, k)

        bf = ttk.Frame(f)
        bf.grid(row=5, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(bf, text="Cancel", command=win.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(bf, text="Add", style="Accent.TButton", command=ok).pack(side="right")
        e.focus_set()
        win.bind("<Return>", lambda _e: ok())

    def add_watchpoint(self, addr: int, size: int, wtype: str) -> None:
        """Hardware watchpoint from another tab (Scanner: 'find out what writes to this address').
        Armed now when attached, otherwise when you press Attach."""
        if size not in WATCH_LEN or wtype not in WATCH_TYPE:
            self.app.log_line(f"debugger: unsupported watchpoint size {size} / type {wtype}")
            return
        if any(b["kind"] == "wp" and b["addr"] == addr and b.get("wtype") == wtype for b in self.bps):
            self.app.log_line(f"debugger: a {wtype} watchpoint on 0x{addr:X} already exists")
            return
        slot = self._free_slot("wp")
        if slot is None:
            self.app.log_line("debugger: all 4 hardware watchpoints are in use - remove one first")
            return
        b: Bp = {"kind": "wp", "slot": slot, "addr": addr, "enabled": True, "hits": 0, "applied": False,
                 "orig": None, "len": size, "wtype": wtype}

        def work() -> None:
            if self.attached:
                self._apply(b)
            self.bps.append(b)
            self.app.root.after(0, self._bps_changed)

        self.app._run_bg(work, "Setting watchpoint...")
        if not self.attached:
            what = "hardware execute breakpoint" if wtype == "exec" else f"{wtype} watchpoint"
            self.app.log_line(f"debugger: {what} on 0x{addr:X} added - press Attach to arm it")

    def on_bp_toggle_enabled(self) -> None:
        b = self._selected_bp()
        if not b:
            return

        def work() -> None:
            if self.attached:
                self._set_armed(b, not b["enabled"])
            else:
                b["enabled"] = not b["enabled"]
            self.app.root.after(0, self._bps_changed)

        self.app._run_bg(work, "Updating breakpoint...")

    def on_bp_remove(self) -> None:
        b = self._selected_bp()
        if b:
            self._remove([b])

    def on_bp_remove_all(self) -> None:
        if self.bps and messagebox.askyesno("Breakpoints", "Remove all breakpoints and watchpoints?"):
            self._remove(list(self.bps))

    def _bps_changed(self) -> None:
        self._fill_bps()
        self._refresh_marks()

    def _fill_bps(self) -> None:
        self.bp_tree.delete(*self.bp_tree.get_children())
        for i, b in enumerate(self.bps):
            kind = "BP int3" if b["kind"] == "bp" else (
            "HW exec" if b["wtype"] == "exec" else f"HW {'write' if b['wtype'] == 'write' else 'rd/wr'} {b['len']}B")
            if not b["enabled"]:
                on = "off"
            else:
                on = "on" if b["applied"] else "pending"
            self.bp_tree.insert("", "end", iid=str(i), values=(
                b["slot"], kind, f"{b['addr']:016X}", label_for(self._maps, b["addr"]), on, b["hits"]))

    def _refresh_marks(self) -> None:
        self.view.refresh_marks(self.rip_for_marks(), self.bp_addrs())
        dt = getattr(self.app, "disassembler", None)
        if dt:
            dt.refresh_marks()

    # ============================================= run control
    # ---- single-step.  NB: after a breakpoint hit the console has ALREADY executed the instruction at RIP
    # (it steps over its own int3 before reporting), so the first "step" from there needs no execution.
    def _advance(self) -> StopEvent:
        """Stop event for 'execute one instruction' (worker thread)."""
        if not self.listener:
            raise RuntimeError("debugger channel is not running")
        if self._prestepped and self._real_blob and self.evt:
            e = self.evt                       # the live registers already are the result of that step
            return StopEvent(e.lwpid, e.status, e.tdname, self._real_blob, parse_regs(self._real_blob), 0,
                             self._real_fpu)
        return self._step_native()

    def _step_native(self) -> StopEvent:
        waiter = self.listener.arm_waiter()
        try:
            if self._mode == "native thread" and self.evt:
                self.client.debug_step_thread(self.evt.lwpid)
            else:
                self.client.debug_step()
        except ProtocolError as exc:
            self.listener.disarm_waiter()
            raise RuntimeError(f"{exc}. The console only steps a game that is stopped at an event - "
                               "try 'native thread' in 'Step method', or Detach and Attach again.") from None
        try:
            return waiter.get(timeout=8)
        except queue.Empty:
            self.listener.disarm_waiter()
            raise RuntimeError(
                "no stop event came back after the step. The console connects to port 755 on this PC - "
                "check the firewall and that nothing else is using 755.") from None

    def _post_stop(self, evt: StopEvent, stepped: bool) -> None:
        self.app.root.after(0, lambda: self._on_stop(evt, stepped))

    def _resume_locked(self) -> bool:
        """Continue the game (worker thread).  The console already stepped off the breakpoint it reported,
        so nothing has to be stepped here; queued breakpoint disarms are done first (they resume the game
        anyway, which is exactly what we want now)."""
        if self._temp and self._temp["done"]:
            self._drop_temp()
        self._flush_disarm()
        self.client.debug_continue(0)
        self.running = True
        self.stopped = False
        self._code_cache = []                   # the game ran: code may have changed (cheats, unpacking)
        self.app.root.after(0, self._after_resume)
        return True

    def _after_resume(self) -> None:
        self._set_status()
        self._refresh_marks()

    def _drop_temp(self) -> None:
        """Forget the temporary breakpoint; its disarm waits for the next resume (disarming now would resume the game)."""
        t, self._temp = self._temp, None
        tb = t["b"] if t else None
        if tb is not None and tb["applied"]:
            tb["enabled"] = False
            if tb not in self._to_disarm:
                self._to_disarm.append(tb)

    def _run_to_locked(self, addr: int, min_rsp: int) -> None:
        self._drop_temp()
        tb = None
        if self._bp_at(addr) is None:                       # a user breakpoint there already stops us
            busy = {p["slot"] for p in self._to_disarm if p["kind"] == "bp"}
            slot = next((s for s in self.RUN_SLOTS if s not in busy), None)
            if slot is None:
                raise RuntimeError("temporary breakpoint slots are busy - press Continue once, then retry")
            tb = {"kind": "bp", "slot": slot, "addr": addr, "enabled": True, "hits": 0, "applied": False, "orig": None}
            self._apply(tb)
        self._temp = {"b": tb, "addr": addr, "min_rsp": min_rsp, "done": False}
        self._resume_locked()

    def on_pause(self) -> None:
        if not (self.attached and self.running):
            return

        def work() -> None:
            self.client.debug_continue(1)  # SIGSTOP; the stop event arrives on port 755

        self.app._run_bg(work, "Pausing...")

    def on_continue(self) -> None:
        if not self._need_stopped():
            return

        def work() -> None:
            self._resume_locked()

        self.app._run_bg(work, "Continuing...")

    def on_step_into(self) -> None:
        if not self._need_stopped():
            return

        def work() -> None:
            self._drop_temp()
            self._post_stop(self._advance(), True)

        self.app._run_bg(work, "Stepping...")

    def on_step_over(self) -> None:
        if not self._need_stopped():
            return
        pid = self.pid
        overrides = self.bp_overrides()

        def work() -> None:
            self._drop_temp()
            rip, rsp = self.regs["rip"], self.regs["rsp"]
            insns = [i for i in self._code_cache if i.addr == rip][:1]
            if not insns:
                insns, _ = disasm.disassemble(self.client, pid, rip, 0x20, 1, overrides)
            if insns and insns[0].kind & K_CALL:
                # run until the call returns (RSP is back to its value before the call).  If the console already
                # executed the call we are inside the callee: the same temporary breakpoint still gets us out.
                self._run_to_locked(insns[0].addr + insns[0].size, rsp)
            else:
                self._post_stop(self._advance(), True)

        self.app._run_bg(work, "Stepping over...")

    def on_step_out(self) -> None:
        if not self._need_stopped():
            return
        if "frames" not in self._stale:
            target = next((f for f in self._frames if f.get("valid")), None)
            if not target:
                self.app.log_line("step out: no caller found on the stack (see the Call stack / Stack tabs)")
                return
            ret, slot = target["ret"], target["slot"]

            def work() -> None:
                self._run_to_locked(ret, slot + 8)  # after RET, RSP = slot + 8

            self.app._run_bg(work, f"Running until return to 0x{ret:X}...")
            return
        regs = dict(self.regs)

        def work_lazy() -> None:        # the call stack was not loaded for this stop: find the caller now
            stack = self._read_stack_bytes(self.client, self.pid, regs["rsp"])
            frames = self._build_frames(regs, stack, self.bp_overrides())
            target = next((f for f in frames if f.get("valid")), None)
            if not target:
                self.app.root.after(0, lambda: self.app.log_line(
                    "step out: no caller found on the stack (see the Call stack / Stack tabs)"))
                return
            self._run_to_locked(target["ret"], target["slot"] + 8)

        self.app._run_bg(work_lazy, "Stepping out...")

    def on_run_to_selected(self) -> None:
        ins = self.view.selected()
        if ins:
            self.run_to_cursor(ins.addr)
        else:
            self.app.log_line("select an instruction line first")

    def run_to_cursor(self, addr: int) -> None:
        if not self._need_stopped():
            return

        def work() -> None:
            self._run_to_locked(addr, 0)

        self.app._run_bg(work, f"Running to 0x{addr:X}...")

    # ================================================ stop handling
    def _on_stop(self, evt: StopEvent, stepped: bool = False) -> None:
        self._when_idle(lambda: self._handle_stop(evt, stepped))

    def _handle_stop(self, evt: StopEvent, stepped: bool) -> None:
        self.attached = True
        self.running = False
        self.stopped = True
        self.evt = evt
        self.prev_regs = dict(self.regs)
        self.regs = dict(evt.regs)
        self.regs_blob = evt.regs_blob
        self._notes = []
        self._set_status()
        self.app._run_bg(lambda: self._stop_work(evt, stepped), "Reading debugger state...")

    def _stop_work(self, evt: StopEvent, stepped: bool) -> None:
        client, pid, root = self.client, self.pid, self.app.root
        gen = self._stop_gen
        t0 = time.monotonic()
        regs, blob = dict(evt.regs), evt.regs_blob
        notes: list[str] = []
        rip = regs["rip"]

        # 1. The console rewinds RIP onto a hit breakpoint itself, and steps over the breakpointed instruction
        #    BEFORE reporting.  So the packet shows the state before that instruction while the thread already
        #    sits after it: compare with the live registers.
        hit = None if stepped else self._bp_at(rip)
        self.regs, self.regs_blob = regs, blob
        self._real_blob, self._prestepped = b"", False
        self._real_fpu = b""                    # fetched when an XMM register is edited
        live_rip = rip
        try:
            live = client.debug_getregs(evt.lwpid)
            self._real_blob = live
            live_rip = parse_regs(live)["rip"]
            self._prestepped = live_rip != rip
        except Exception:
            pass
        if self._prestepped:
            notes.append(f"console already ran this instruction (thread is at 0x{live_rip:X}); Step moves on from there")

        # 2. temporary breakpoint (step over / out / run to cursor)
        tmp = self._temp
        if tmp and not tmp["done"]:
            if rip == tmp["addr"] and hit is None and regs["rsp"] < tmp["min_rsp"]:
                # same address but a deeper (recursive) frame - keep going silently
                self._resume_locked()
                return
            tmp["done"] = True        # stays armed until the next resume: disarming now would resume the game

        if hit:
            hit["hits"] += 1
            notes.append(f"breakpoint #{hit['slot']} hit")
        if evt.dr6 & 0xF:
            for i in range(4):
                if evt.dr6 & (1 << i):
                    w = next((b for b in self.bps if b["kind"] == "wp" and b["slot"] == i), None)
                    if w:
                        w["hits"] += 1
                        notes.append(f"watchpoint {i} on 0x{w['addr']:X}")
        if evt.signal not in (5, 17):
            notes.append(evt.signame)
        self._notes = notes

        # 3. registers + code first.  The memory map is reused while RIP/RSP stay inside known mappings.
        if self._maps_stale(rip, regs["rsp"]):
            try:
                self._maps = client.maps(pid)
                self.app._maps_cache = self._maps
                self._maps_time = time.monotonic()
            except Exception:
                pass
        overrides = self.bp_overrides()
        insns = self._cached_code(rip, overrides)
        if insns is None:
            insns = []
            try:
                insns, _ = disasm.disassemble(client, pid, rip, 0x400, 64, overrides)
                self._code_cache, self._code_key = insns, tuple(sorted(overrides.items()))
            except Exception as exc:
                self._code_cache = []
                root.after(0, lambda e=exc: self.app.log_line(f"debugger: cannot disassemble at RIP: {e}"))
        fpu = evt.fpu_blob if fpu_ok(evt.fpu_blob) else b""     # the event packet carries XMM: no extra request
        self._stale = {"frames", "threads"} | (set() if fpu else {"fpu"})
        took = time.monotonic() - t0
        root.after(0, lambda: self._show_stop(evt, regs, blob, insns, fpu, took))

        # 4. only the lower panel that is on screen; the others load when their tab is opened
        self._load_lazy(self._tab_now, gen)

    def _maps_stale(self, rip: int, rsp: int) -> bool:
        if not self._maps or time.monotonic() - self._maps_time > 15:
            return True
        return not (any(m.start <= rip < m.end for m in self._maps) and any(m.start <= rsp < m.end for m in self._maps))

    def _cached_code(self, rip: int, overrides: dict) -> Optional[list[Insn]]:
        """Reuse the last disassembly while stepping inside it (no breakpoint change, game not resumed)."""
        c = self._code_cache
        if not c or self._code_key != tuple(sorted(overrides.items())):
            return None
        for i, ins in enumerate(c):
            if ins.addr == rip:
                return c if len(c) - i >= 16 else None
        return None

    # ---- lower panels (loaded on demand)
    _TAB_NEEDS = {"Call stack": "frames", "Stack (RSP)": "frames", "Threads": "threads", "XMM / FPU": "fpu"}

    def _on_tab_changed(self, _e=None) -> None:
        try:
            self._tab_now = self._nb.tab(self._nb.select(), "text")
        except tk.TclError:
            return
        need = self._TAB_NEEDS.get(self._tab_now)
        if self.stopped and need in self._stale:
            gen = self._stop_gen
            self.app._run_bg(lambda: self._load_lazy(self._tab_now, gen), "Loading debugger panel...")

    def _load_lazy(self, tab: str, gen: int) -> None:
        """Worker thread: load what `tab` shows for the current stop (skipped when a newer action came in)."""
        need = self._TAB_NEEDS.get(tab)
        if need not in self._stale or gen != self._stop_gen or not self.stopped:
            return
        client, pid, root = self.client, self.pid, self.app.root
        regs = dict(self.regs)
        evt = self.evt
        if need == "frames":
            stack = self._read_stack_bytes(client, pid, regs["rsp"])
            overrides = self.bp_overrides()
            frames = self._build_frames(regs, stack, overrides)
            if gen != self._stop_gen:
                return
            starts = self._func_starts([regs["rip"]] + [f["ret"] for f in frames], overrides)
            for f in frames:
                f["func"] = starts.get(f["ret"])
            self._rip_func = starts.get(regs["rip"])
            if gen != self._stop_gen:
                return
            self._stale.discard("frames")
            self._frames, self._stack_bytes = frames, stack

            def show() -> None:
                self._fill_frames(regs["rip"], frames)
                self._fill_stack(regs, stack, frames)
            root.after(0, show)
        elif need == "threads":
            threads: list[tuple[int, str]] = []
            try:
                for tid in client.debug_threads()[:64]:
                    if tid not in self._thread_names:
                        try:
                            self._thread_names[tid] = client.debug_thread_info(tid)[1]
                        except Exception:
                            self._thread_names[tid] = ""
                    threads.append((tid, self._thread_names[tid]))
            except Exception:
                pass
            if gen != self._stop_gen:
                return
            self._stale.discard("threads")
            lwp = evt.lwpid if evt else 0

            def show_t() -> None:
                self.thr_tree.delete(*self.thr_tree.get_children())
                for tid, name in threads:
                    self.thr_tree.insert("", "end", iid=str(tid),
                                         values=(tid, name, "\u25c4 stopped here" if tid == lwp else ""))
            root.after(0, show_t)
        elif need == "fpu" and evt:
            try:
                fpu = client.debug_getfpregs(evt.lwpid)
            except Exception as exc:
                root.after(0, lambda e=exc: self.app.log_line(f"debugger: cannot read XMM registers: {e}"))
                return
            if gen != self._stop_gen:
                return
            self._stale.discard("fpu")
            self._real_fpu = fpu

            def show_f() -> None:
                if self.disp_lwp == evt.lwpid:
                    self.disp_fpu = fpu
                    self._fill_xmm()
            root.after(0, show_f)

    def _call_sites(self, rets: list[int], overrides: dict) -> dict[int, Optional[Insn]]:
        """ret address -> the CALL right before it.  One bulk read for all of them when the console allows."""
        out: dict[int, Optional[Insn]] = {}
        rets = list(dict.fromkeys(rets))
        if not rets:
            return out
        if self._bulk_ok and len(rets) > 1:
            try:
                blobs = self.client.read_multi(self.pid, [(r - 8, 8) for r in rets])
                for r, b in zip(rets, blobs):
                    out[r] = disasm.call_site_from_bytes(b, r, overrides)
                return out
            except ProtocolError as exc:
                if not self.client.connected:
                    raise
                self._bulk_ok = False
                self.app.root.after(0, lambda e=exc: self.app.log_line(
                    f"debugger: bulk read not available ({e}) - checking frames one by one"))
        for r in rets:
            out[r] = disasm.find_call_site(self.client, self.pid, r, overrides)
        return out

    def _code_around(self, addrs: list[int], overrides: dict) -> None:
        """Fill self._fcode[a] = (function start or None, bytes start..a, bytes a..a+0x40, bytes a-8..a)
        for code addresses: reads the code before each one (bulk when possible) and scans back for the
        padding / prologue a function starts with."""
        todo = [a for a in dict.fromkeys(addrs) if a and a not in self._fcode]
        for span in (0x1000, 0x4000):
            if not todo:
                break
            reqs = []
            for a in todo:
                lo, hi = a - span, a + 0x40
                for m in self._maps:                     # stay inside the mapping
                    if m.start <= a < m.end:
                        lo, hi = max(lo, m.start), min(hi, m.end)
                        break
                reqs.append((lo, max(0, hi - lo)))
            blobs: list[bytes] = []
            if self._bulk_ok and len(reqs) > 1:
                try:
                    blobs = self.client.read_multi(self.pid, reqs)
                except ProtocolError:
                    if not self.client.connected:
                        raise
                    blobs = []
            if len(blobs) != len(reqs):
                blobs = []
                for lo, n in reqs:
                    try:
                        blobs.append(self.client.read(self.pid, lo, n) if n > 0 else b"")
                    except ProtocolError:
                        if not self.client.connected:
                            raise
                        blobs.append(b"")
                    except Exception:
                        blobs.append(b"")
            left = []
            for a, (lo, n), data in zip(todo, reqs, blobs):
                if len(data) != n or n == 0 or a - lo > n:
                    self._fcode[a] = (None, b"", b"", b"")
                    continue
                if overrides:                            # our int3 breakpoints must not look like padding
                    buf = bytearray(data)
                    for ba, bv in overrides.items():
                        if lo <= ba < lo + n:
                            buf[ba - lo] = bv
                    data = bytes(buf)
                k = a - lo
                st = disasm.func_start_in(data, lo, a)
                if st is None and span == 0x1000 and k == span:
                    left.append(a)                       # long function: look further back
                    continue
                self._fcode[a] = (st, data[st - lo:k] if st is not None else b"", data[k:], data[max(0, k - 8):k])
            todo = left
        for a in todo:
            self._fcode.setdefault(a, (None, b"", b"", b""))
        if len(self._fcode) > 4096:
            keep = {a: self._fcode[a] for a in addrs if a in self._fcode}
            self._fcode.clear()
            self._fcode.update(keep)

    def _func_starts(self, addrs: list[int], overrides: dict) -> dict[int, Optional[int]]:
        """Code address -> estimated start of its function (None = not found)."""
        self._code_around(addrs, overrides)
        return {a: self._fcode.get(a, (None,))[0] for a in addrs if a}

    def _func_text(self, start: Optional[int], addr: int) -> str:
        if start is None:
            return "?"
        w = self._where(start) if self.rel_addr.get() else ""
        return f"{w or f'{start:X}'} +0x{addr - start:X}"

    @staticmethod
    def _read_stack_bytes(client, pid: int, rsp: int) -> bytes:
        """Stack memory from rsp: 4 KB, less near the top of the stack mapping."""
        for n in (0x1000, 0x400, 0x200, 0x80):
            try:
                return client.read(pid, rsp, n)
            except ProtocolError:
                if not client.connected:
                    raise
            except Exception:
                pass
        return b""

    def _build_frames(self, regs: dict, stack: bytes, overrides: dict) -> list[dict]:
        """Caller frames, innermost first.

        1. The unwinder (unwind.py) works out where each function keeps its return address from its
           prologue / epilogue, so frameless functions (no push rbp) are not skipped.
        2. Where it cannot go on, the console's RBP-chain walk fills in the outer frames.
        3. Without either, the stack is scanned for return addresses.
        Every frame's return address must follow a CALL."""
        client, pid = self.client, self.pid
        rsp0 = regs["rsp"]
        extra: dict[int, bytes] = {}

        def read_u64(addr: int) -> Optional[int]:
            off = addr - rsp0
            if 0 <= off <= len(stack) - 8:
                return int.from_bytes(stack[off:off + 8], "little")
            page = addr & ~0xFFF
            if page not in extra:
                if len(extra) > 16:
                    return None
                try:
                    extra[page] = client.read(pid, page, 0x1000)
                except ProtocolError:
                    if not client.connected:
                        raise
                    extra[page] = b""
                except Exception:
                    extra[page] = b""
            blob = extra[page]
            o = addr - page
            return int.from_bytes(blob[o:o + 8], "little") if o + 8 <= len(blob) else None

        # the console's RBP walk: one request, and its return addresses warm the code cache below
        walk = []
        try:
            walk = [f for f in client.read_stack(pid, regs["rbp"], rsp0, 24) if is_exec(self._maps, f.ret_addr)]
        except ProtocolError:
            if not client.connected:
                raise
        except Exception:
            pass
        self._code_around([regs["rip"]] + [f.ret_addr for f in walk], overrides)

        def code_info(addr: int):
            self._code_around([addr], overrides)
            st, entry, here, _before = self._fcode[addr]
            return st, entry, here

        def call_at(ret: int):
            if not is_exec(self._maps, ret):
                return None
            self._code_around([ret], overrides)
            return disasm.call_site_from_bytes(self._fcode[ret][3], ret)   # bytes already have the overrides

        out: list[dict] = []
        try:
            for f in unwind.walk(regs["rip"], rsp0, regs["rbp"], code_info, read_u64, call_at, 32):
                out.append({"ret": f.ret, "slot": f.slot, "call": f.call, "src": f.how, "valid": True})
        except ProtocolError:
            if not client.connected:
                raise
        except Exception:
            out = []

        # outer frames the unwinder could not reach: the RBP chain, above the last unwound slot
        last = out[-1]["slot"] if out else -1
        rest = [f for f in walk if f.rbp + 8 > last]
        if rest:
            calls = self._call_sites([f.ret_addr for f in rest], overrides)
            for f in rest:
                call = calls.get(f.ret_addr)
                if call:
                    out.append({"ret": f.ret_addr, "slot": f.rbp + 8, "call": call, "src": "rbp", "valid": True})
        if out:
            return out
        cands = []
        for i in range(0, max(0, len(stack) - 7), 8):
            v = int.from_bytes(stack[i : i + 8], "little")
            if is_exec(self._maps, v):
                cands.append((rsp0 + i, v))
        calls = self._call_sites([v for _s, v in cands], overrides)
        for slot, v in cands:
            call = calls.get(v)
            if call:
                out.append({"ret": v, "slot": slot, "call": call, "src": "scan", "valid": True})
                if len(out) >= 16:
                    break
        return out

    def _show_stop(self, evt: StopEvent, regs: dict, blob: bytes, insns: list[Insn], fpu: bytes = b"",
                   took: float = 0.0) -> None:
        self.prev_fpu = self.disp_fpu if self.disp_lwp == evt.lwpid else b""
        self.disp_lwp, self.disp_regs, self.disp_blob = evt.lwpid, regs, blob
        self.disp_fpu = fpu
        self._fill_regs(regs, self.prev_regs)
        self._fill_xmm()
        rip = regs["rip"]
        self.view.load(insns, rip=rip, bps=self.bp_addrs(), select=rip)
        self.view_var.set(f"0x{rip:X}")

        # lower panels: cleared now, filled when loaded (the visible one loads right away)
        self._frames, self._stack_bytes, self._rip_func = [], b"", None
        self.frame_tree.delete(*self.frame_tree.get_children())
        self.stack_tree.delete(*self.stack_tree.get_children())
        self.frame_tree.insert("", "end", iid="none", values=("", "", "loading...", "", ""))
        for iid in self.thr_tree.get_children():
            self.thr_tree.set(iid, "state", "\u25c4 stopped here" if iid == str(evt.lwpid) else "")
        self._fill_bps()
        self._refresh_marks()
        self._set_status()
        self.app.log_line(f"stopped at 0x{rip:X} ({label_for(self._maps, rip) or '?'}) "
                          f"thread {evt.lwpid}  {evt.signame}" + (f"  [{'; '.join(self._notes)}]" if self._notes else "")
                          + f"  ({took * 1000:.0f} ms)")

    def _where(self, addr: int) -> str:
        """Info text for an address: absolute by default, module+offset if the checkbox is ticked."""
        return describe_addr(self._maps, addr, self.rel_addr.get()) if self._maps else ""

    def _fill_frames(self, rip: int, frames: list[dict]) -> None:
        self.frame_tree.delete(*self.frame_tree.get_children())
        rip_func = self._rip_func
        self.frame_tree.insert("", "end", iid="f0", values=(
            0, f"{rip:016X}", self._where(rip), self._func_text(rip_func, rip), "(current function)"))
        callee = rip_func                                # the function one row up = what this frame called
        for i, f in enumerate(frames, 1):
            call = f["call"]
            text = f"{call.addr:X}: {call.text}" if call else ""
            if call and call.target is None and callee is not None:
                text += f"   \u2192 {self._where(callee) if self.rel_addr.get() else f'{callee:X}'}"
            self.frame_tree.insert("", "end", iid=f"f{i}", values=(
                i, f"{f['ret']:016X}", self._where(f["ret"]), self._func_text(f.get("func"), f["ret"]), text))
            callee = f.get("func")
        if not frames:
            self.frame_tree.insert("", "end", iid="none", values=("", "", "no caller found", "", ""))

    def _fill_stack(self, regs: dict, stack: bytes, frames: list[dict]) -> None:
        self.stack_tree.delete(*self.stack_tree.get_children())
        ret_slots = {f["slot"]: f for f in frames}
        base = regs["rsp"]
        for i in range(0, min(len(stack), 0x400) - 7, 8):     # 128 slots: enough to read, quick to fill
            v = int.from_bytes(stack[i : i + 8], "little")
            slot = base + i
            info = self._where(v)
            tags: tuple = ()
            if slot in ret_slots:
                info = f"\u25c4 return into {info}"
                tags = ("ret",)
            self.stack_tree.insert("", "end", iid=f"s{i}", values=(f"{slot:016X}", f"{v:016X}", info), tags=tags)

    def _relabel(self) -> None:
        """The absolute / module+offset checkbox changed: redraw the info columns."""
        if self.disp_regs:
            self._fill_regs(self.disp_regs, {})
        if self.stopped and self.regs and self._stack_bytes:
            self._fill_frames(self.regs["rip"], self._frames)
            self._fill_stack(self.regs, self._stack_bytes, self._frames)

    def _fill_regs(self, regs: dict, prev: dict) -> None:
        for name in REG_DISPLAY:
            v = regs.get(name, 0)
            size = REG_INFO[name][1]
            text = f"{v:016X}" if size == 8 else f"{v:08X}" if size == 4 else f"{v:04X}"
            if name == "rflags":
                info = flags_text(v)
            else:
                info = self._where(v) if size == 8 else ""
            changed = prev and prev.get(name) is not None and prev.get(name) != v
            self.reg_tree.item(name, values=(name.upper(), text, info), tags=("chg",) if changed else ())

    # ------------------------------------------------ XMM / YMM
    def _fill_xmm(self) -> None:
        fpu, prev, fmt, ymm = self.disp_fpu, self.prev_fpu, self.xmm_fmt.get(), self.xmm_ymm.get()
        have = fpu_ok(fpu)
        for i in range(16):
            name = f"{'YMM' if ymm else 'XMM'}{i}"
            if not have:
                self.xmm_tree.item(f"x{i}", values=(name, "", ""), tags=())
                continue
            d = vec_get(fpu, i, ymm)
            changed = fpu_ok(prev) and vec_get(prev, i, ymm) != d
            self.xmm_tree.item(f"x{i}", values=(name, vec_text(d, fmt), vec_hex(d)),
                               tags=("chg",) if changed else ())
        if have:
            m = mxcsr_get(fpu)
            changed = fpu_ok(prev) and mxcsr_get(prev) != m
            self.xmm_tree.item("mxcsr", values=("MXCSR", mxcsr_text(m), f"{m:08X}"),
                               tags=("chg",) if changed else ())
        else:
            self.xmm_tree.item("mxcsr", values=("MXCSR", "", ""), tags=())

    def _xmm_live(self) -> bool:
        return bool(self._prestepped and self.evt and self.disp_lwp == self.evt.lwpid)

    def _edit_xmm(self, row: str) -> None:
        if not row or not self.stopped or not fpu_ok(self.disp_fpu):
            return
        fmt, ymm = self.xmm_fmt.get(), self.xmm_ymm.get()
        live = self._xmm_live()
        try:
            if row == "mxcsr":
                cur = mxcsr_get(self.disp_fpu)
                text = simpledialog.askstring("Edit MXCSR", "New MXCSR value (hex / expression):",
                                              initialvalue=f"0x{cur:X}", parent=self.app.root)
                if not text:
                    return
                v = self.app.eval_full(text)

                def patch(fpu: bytes) -> bytes:
                    return mxcsr_set(fpu, v)
                label = f"MXCSR = 0x{v & 0xFFFFFFFF:X}"
            else:
                i = int(row[1:])
                name = f"{'YMM' if ymm else 'XMM'}{i}"
                old = vec_get(self.disp_fpu, i, ymm)
                n = VEC_FORMATS[fmt][1]
                hint = (f"{len(old) // n} values as {fmt}, lane 0 first, separated by commas.\n"
                        "Lanes you leave out keep their value.")
                if fmt.startswith("Float") or fmt.startswith("Double") or fmt.endswith("(dec)"):
                    hint += f"\nOr 0x<hex> for the whole {8 * len(old)}-bit register."
                text = simpledialog.askstring(f"Edit {name}", hint, initialvalue=vec_text(old, fmt),
                                              parent=self.app.root)
                if not text:
                    return
                data = vec_parse(text, fmt, old)

                def patch(fpu: bytes) -> bytes:
                    return vec_set(fpu, i, data)
                label = f"{name} = {vec_text(data, fmt)}"
            shown = patch(self.disp_fpu)
        except Exception as exc:
            self.app._fail(exc)
            return
        lwp = self.disp_lwp

        def work() -> None:
            # always patch the thread's current image (complete xsave, valid header) and send it back
            blob = patch(self.client.debug_getfpregs(lwp))
            self.client.debug_setfpregs(lwp, blob)

            def done() -> None:
                if self.evt and lwp == self.evt.lwpid:
                    self._real_fpu = blob
                if live:
                    self.app.log_line("(written to the live registers - the table shows the state before the "
                                      "instruction the console already executed)")
                self.prev_fpu, self.disp_fpu = b"", shown
                self._fill_xmm()
                self.app.log_line(label)
            self.app.root.after(0, done)

        self.app._run_bg(work, "Writing XMM register...")

    def _xmm_row_texts(self, row: str) -> tuple[str, str, str]:
        vals = self.xmm_tree.item(row, "values")
        return str(vals[0]), str(vals[1]), str(vals[2])

    def _copy_xmm_key(self) -> str:
        sel = self.xmm_tree.selection()
        if sel and fpu_ok(self.disp_fpu):
            self._copy(self._xmm_row_texts(sel[0])[1])
        return "break"

    def _all_xmm_text(self) -> str:
        return "\n".join(f"{n} = {v}   [{h}]" for n, v, h in
                         (self._xmm_row_texts(r) for r in self.xmm_tree.get_children()))

    def _xmm_menu(self, event) -> None:
        row = self.xmm_tree.identify_row(event.y)
        if not row or not fpu_ok(self.disp_fpu):
            return
        self.xmm_tree.selection_set(row)
        name, val, hx = self._xmm_row_texts(row)
        items = [
            ("Copy value", lambda: self._copy(val)),
            ("Copy as hex", lambda: self._copy("0x" + hx.replace(" ", ""))),
        ]
        if row != "mxcsr":
            d = vec_get(self.disp_fpu, int(row[1:]), False)
            f0 = vec_text(d[:4], "Float x4")
            d0 = vec_text(d[:8], "Double x2")
            items += [
                (f"Copy lane 0 as float   {f0}", lambda: self._copy(f0)),
                (f"Copy lane 0 as double   {d0}", lambda: self._copy(d0)),
            ]
        items += [
            ("Copy all XMM registers", lambda: self._copy(self._all_xmm_text())),
            None,
            (f"Edit {name}...", lambda: self._edit_xmm(row), self.stopped),
        ]
        self._popup(event, items)

    # ================================================== other actions
    def on_reg_edit(self, event) -> None:
        self._edit_reg(self.reg_tree.identify_row(event.y))

    def _edit_reg(self, row: str) -> None:
        if not row or not self.stopped or not self.disp_blob:
            return
        cur = self.disp_regs.get(row, 0)
        text = simpledialog.askstring("Edit register", f"New value for {row.upper()} (hex / expression):",
                                      initialvalue=f"0x{cur:X}", parent=self.app.root)
        if not text:
            return
        try:
            value = self.app.eval_full(text)
        except Exception as exc:
            self.app._fail(exc)
            return
        lwp = self.disp_lwp
        # after a breakpoint hit the table shows the state BEFORE the instruction, but the register file that
        # can actually be changed is the live one (after it)
        live = bool(self._prestepped and self.evt and lwp == self.evt.lwpid and self._real_blob)
        blob = patch_reg(self._real_blob if live else self.disp_blob, row, value)
        shown = patch_reg(self.disp_blob, row, value) if live else blob

        def work() -> None:
            self.client.debug_setregs(lwp, blob)
            regs = parse_regs(shown)

            def done() -> None:
                if live:
                    self._real_blob = blob
                    self.app.log_line("(written to the live registers - the table shows the state before the "
                                      "instruction the console already executed)")
                self.disp_blob, self.disp_regs = shown, regs
                if self.evt and lwp == self.evt.lwpid:
                    self.regs, self.regs_blob = regs, shown
                self._fill_regs(regs, {})
                self.app.log_line(f"{row.upper()} = 0x{regs[row]:X}")
                if row == "rip":
                    self.on_view_rip()
            self.app.root.after(0, done)

        self.app._run_bg(work, "Writing register...")

    # ------------------------------------------------ copy / "view in hex editor"
    def _copy(self, text: str) -> None:
        self.parent.clipboard_clear()
        self.parent.clipboard_append(text)
        self.app.log_line("copied: " + (text if len(text) <= 80 and "\n" not in text else text.splitlines()[0][:77] + "..."))

    def _popup(self, event, items: list) -> None:
        """items: (label, callback[, enabled]) or None for a separator."""
        menu = tk.Menu(self.parent, tearoff=0)
        for it in items:
            if it is None:
                menu.add_separator()
            else:
                menu.add_command(label=it[0], command=it[1],
                                 state="normal" if (len(it) < 3 or it[2]) else "disabled")
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_reg_key(self) -> str:
        sel = self.reg_tree.selection()
        if sel and sel[0] in self.disp_regs:
            self._copy(f"0x{self.disp_regs[sel[0]]:X}")
        return "break"

    def _all_regs_text(self) -> str:
        return "\n".join(f"{n.upper()} = 0x{self.disp_regs[n]:X}" for n in REG_DISPLAY if n in self.disp_regs)

    def _reg_menu(self, event) -> None:
        row = self.reg_tree.identify_row(event.y)
        if not row or row not in self.disp_regs:
            return
        self.reg_tree.selection_set(row)
        v = self.disp_regs[row]
        name = row.upper()
        is_ptr = REG_INFO[row][1] == 8 and row != "rflags"
        code = is_ptr and is_exec(self._maps, v)
        self._popup(event, [
            (f"Copy value   0x{v:X}", lambda: self._copy(f"0x{v:X}")),
            ("Copy as plain hex", lambda: self._copy(f"{v:X}")),
            ("Copy as decimal", lambda: self._copy(str(v))),
            (f"Copy  {name} = 0x...", lambda: self._copy(f"{name} = 0x{v:X}")),
            ("Copy all registers", lambda: self._copy(self._all_regs_text())),
            None,
            ("View in hex editor", lambda: self.app._hex_goto_value(v, 0x100), is_ptr),
            ("View in code view (this tab)", lambda: self.show_code(v), code),
            ("Show in Disassembler tab", lambda: self.app.show_in_disassembler(v), code),
            None,
            (f"Edit {name}...", lambda: self._edit_reg(row), self.stopped),
        ])

    def _tree_row_values(self, tree, event):
        row = tree.identify_row(event.y)
        if not row:
            return None
        tree.selection_set(row)
        return row, tree.item(row, "values")

    def _copy_stack_key(self) -> str:
        sel = self.stack_tree.selection()
        if sel:
            vals = self.stack_tree.item(sel[0], "values")
            self._copy("0x" + str(vals[1]).lstrip("0").upper() if int(vals[1], 16) else "0x0")
        return "break"

    def _stack_menu(self, event) -> None:
        got = self._tree_row_values(self.stack_tree, event)
        if not got:
            return
        _row, vals = got
        try:
            slot, v = int(vals[0], 16), int(vals[1], 16)
        except (ValueError, IndexError):
            return
        code = is_exec(self._maps, v)
        all_lines = "\n".join("  ".join(str(x) for x in self.stack_tree.item(i, "values"))
                              for i in self.stack_tree.get_children())
        self._popup(event, [
            (f"Copy value   0x{v:X}", lambda: self._copy(f"0x{v:X}")),
            (f"Copy slot address   0x{slot:X}", lambda: self._copy(f"0x{slot:X}")),
            ("Copy row", lambda: self._copy("  ".join(str(x) for x in vals))),
            ("Copy whole stack", lambda: self._copy(all_lines)),
            None,
            ("View value in hex editor", lambda: self.app._hex_goto_value(v, 0x100), v != 0),
            ("View this stack slot in hex editor", lambda: self.app._hex_goto_value(slot, 0x100)),
            ("Open value in code view (this tab)", lambda: self.show_code(v), code),
            ("Show value in Disassembler tab", lambda: self.app.show_in_disassembler(v), code),
        ])

    def _frame_menu(self, event) -> None:
        got = self._tree_row_values(self.frame_tree, event)
        if not got:
            return
        row, vals = got
        try:
            ret = int(vals[1], 16)
        except (ValueError, IndexError):
            return
        fs: Optional[int] = None
        if row == "f0":
            fs = self._rip_func
        elif row.startswith("f") and row[1:].isdigit() and 0 < int(row[1:]) <= len(self._frames):
            fs = self._frames[int(row[1:]) - 1].get("func")
        has = fs is not None
        fa = fs or 0
        self._popup(event, [
            (f"Copy return address   0x{ret:X}", lambda: self._copy(f"0x{ret:X}")),
            (f"Copy function start   0x{fa:X}" if has else "Copy function start", lambda: self._copy(f"0x{fa:X}"), has),
            ("Copy row", lambda: self._copy("  ".join(str(x) for x in vals))),
            None,
            ("Open in code view (this tab)", self.on_frame_open),
            ("Open function start in code view", lambda: self.show_code(fa), has),
            ("Show function start in Disassembler tab", lambda: self.app.show_in_disassembler(fa), has),
            ("Log calls to this function (no breakpoint)\u2026", lambda: self.app.open_func_logger(fa), has),
            None,
            ("View return address in hex editor", lambda: self.app._hex_goto_value(ret, 0x100)),
        ])

    def on_thread_show(self) -> None:
        sel = self.thr_tree.selection()
        if not sel or not self.stopped:
            return
        lwp = int(sel[0])

        def work() -> None:
            blob = self.client.debug_getregs(lwp)
            regs = parse_regs(blob)
            try:
                fpu = self.client.debug_getfpregs(lwp)
            except Exception:
                fpu = b""

            def done() -> None:
                self.disp_lwp, self.disp_blob, self.disp_regs = lwp, blob, regs
                self.disp_fpu, self.prev_fpu = fpu, b""
                self._fill_regs(regs, {})
                self._fill_xmm()
                self.app.log_line(f"showing registers of thread {lwp}")
            self.app.root.after(0, done)

        self.app._run_bg(work, "Reading thread registers...")

    def on_thread_ctl(self, suspend: bool) -> None:
        sel = self.thr_tree.selection()
        if not sel or not self.attached:
            return
        lwp = int(sel[0])

        def work() -> None:
            (self.client.debug_suspend_thread if suspend else self.client.debug_resume_thread)(lwp)
            self.app.root.after(0, lambda: self.app.log_line(
                f"thread {lwp} {'suspended' if suspend else 'resumed'}"))

        self.app._run_bg(work, "Thread control...")

    def on_frame_open(self, _event=None) -> None:
        sel = self.frame_tree.selection()
        if not sel or sel[0] in ("none",):
            return
        i = int(sel[0][1:])
        if i == 0:
            self.on_view_rip()
            return
        if i - 1 < len(self._frames):
            f = self._frames[i - 1]
            call = f["call"]
            self.show_code(call.addr if call else f["ret"])

    def on_stack_open(self, _event=None) -> None:
        sel = self.stack_tree.selection()
        if not sel:
            return
        vals = self.stack_tree.item(sel[0], "values")
        try:
            v = int(vals[1], 16)
        except (ValueError, IndexError):
            return
        if is_exec(self._maps, v):
            self.show_code(v)
        else:
            self.app._hex_goto_value(v, 0x100)

    # ----------------------------------------------------- code view
    def on_view_go(self) -> None:
        try:
            self.show_code(self.app.eval_full(self.view_var.get()))
        except Exception as exc:
            self.app._fail(exc)

    def on_view_rip(self) -> None:
        rip = self.rip_for_marks()
        if rip is None:
            self.app.log_line("debugger is not stopped - no RIP yet")
            return
        self.show_code(rip)

    def show_code(self, addr: int) -> None:
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return
        overrides = self.bp_overrides()

        def work() -> None:
            insns, _ = disasm.disassemble(self.client, pid, addr, 0x400, 64, overrides)
            self.app.root.after(0, lambda: self._show_code(addr, insns))

        self.app._run_bg(work, "Disassembling...")

    def _show_code(self, addr: int, insns: list[Insn]) -> None:
        self.view.load(insns, rip=self.rip_for_marks(), bps=self.bp_addrs(), select=addr)
        self.view_var.set(f"0x{addr:X}")

    def _follow(self, ins: Insn) -> None:
        if ins.target is not None:
            if self.view.has(ins.target):
                self.view.select(ins.target)
            else:
                self.show_code(ins.target)
        elif ins.ripref is not None:
            self.app._hex_goto_value(ins.ripref, 0x100)

    def _menu(self, ins: Insn) -> list:
        items: list = []
        if ins.target is not None or ins.ripref is not None:
            items.append(("Follow", lambda: self._follow(ins)))
        items.append(("Toggle breakpoint  (F9)", lambda: self.toggle_bp(ins.addr)))
        items.append(("Breakpoint (choose type)...", lambda: self.open_bp_dialog(ins.addr, "exec")))
        items.append(("Run to here  (F4)", lambda: self.run_to_cursor(ins.addr)))
        items.append(("Log calls to this function (no breakpoint)…", lambda: self.app.open_func_logger(ins.addr)))
        dt = getattr(self.app, "disassembler", None)
        if dt:
            items.append(("Show in Disassembler tab", lambda: self.app.show_in_disassembler(ins.addr)))
        return items
