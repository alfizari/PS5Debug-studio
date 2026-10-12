"""Kernel log tab: live view of the console's /dev/klog.

ps5debug-NG listens on TCP 3232 (console.c klog_server_thread) and streams the kernel log as plain
text to whoever connects.  This is where the console reports crashes, page faults, signals and
"error" lines from the kernel and system services, so it is the first place to look when a call,
a hook or a cheat makes the game fall over.

The reader runs on its own socket and thread, independent of the command connection (port 744),
so it never slows the other tabs.  It reconnects by itself while it is switched on.
"""

from __future__ import annotations

import collections
import queue
import re
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk
from typing import Optional

import theme

KLOG_PORT = 3232
MAX_KEEP = 20000          # lines kept in memory
MAX_SHOW = 5000           # lines kept in the text box

ERR_RX = re.compile(
    r"\b(errors?|fail(?:s|ed|ure)?|fault|panic|abort(?:ed)?|exception|crash(?:ed)?|fatal|assert(?:ion)?|"
    r"sig(?:segv|bus|ill|abrt|fpe|kill|trap)|trap|core ?dump|kill(?:ed)?|invalid|denied|unhandled)\b",
    re.I,
)
WARN_RX = re.compile(r"\b(warn(?:ing)?|timeout|timed out|retry)\b", re.I)


def classify(line: str) -> str:
    if ERR_RX.search(line):
        return "err"
    if WARN_RX.search(line):
        return "warn"
    return ""


class KlogReader:
    """Background reader: connect to host:3232, split the stream into lines, reconnect on drop."""

    def __init__(self, on_line, on_state) -> None:
        self.on_line, self.on_state = on_line, on_state
        self.host = ""
        self.want = False
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, host: str) -> None:
        if self.want and self.host == host and self._thread and self._thread.is_alive():
            return
        self.stop()
        self.host, self.want = host, True
        self._thread = threading.Thread(target=self._run, name="klog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.want = False
        s, self._sock = self._sock, None
        if s:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _run(self) -> None:
        host = self.host
        while self.want and host == self.host:
            self.on_state("connecting", f"connecting to {host}:{KLOG_PORT}...")
            try:
                s = socket.create_connection((host, KLOG_PORT), timeout=5)
            except OSError as exc:
                self.on_state("down", f"cannot reach {host}:{KLOG_PORT} ({exc.strerror or exc}) - retrying")
                self._sleep(3)
                continue
            s.settimeout(1.0)
            self._sock = s
            self.on_state("up", f"connected to {host}:{KLOG_PORT}")
            buf = b""
            idle = 0
            try:
                while self.want:
                    try:
                        chunk = s.recv(65536)
                    except socket.timeout:
                        idle += 1
                        if buf and idle >= 3:         # a partial line with 3 s of silence after it: show it
                            self.on_line(buf.decode("utf-8", "replace"))
                            buf = b""
                        continue
                    idle = 0
                    if not chunk:
                        break
                    buf += chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                    *lines, buf = buf.split(b"\n")
                    for ln in lines:
                        self.on_line(ln.decode("utf-8", "replace"))
            except OSError:
                pass
            finally:
                try:
                    s.close()
                except OSError:
                    pass
                self._sock = None
            if buf:
                self.on_line(buf.decode("utf-8", "replace"))
            if self.want:
                self.on_state("down", "the console closed the kernel log - reconnecting")
                self._sleep(2)
        self.on_state("off", "off")

    def _sleep(self, secs: float) -> None:
        end = time.monotonic() + secs
        while self.want and time.monotonic() < end:
            time.sleep(0.1)


class KlogTab:
    def __init__(self, parent: ttk.Frame, app) -> None:
        self.app, self.parent = app, parent
        st = app.settings
        self.lines: collections.deque = collections.deque(maxlen=MAX_KEEP)   # (time, text, kind)
        self._q: queue.SimpleQueue = queue.SimpleQueue()
        self.auto_var = tk.BooleanVar(value=bool(st.get("klog_auto", True)))
        self.err_only = tk.BooleanVar(value=False)
        self.pause = tk.BooleanVar(value=False)
        self.follow = tk.BooleanVar(value=True)
        self.stamp = tk.BooleanVar(value=True)
        self.to_log = tk.BooleanVar(value=bool(st.get("klog_to_log", False)))
        self.filter_var = tk.StringVar()
        self.state_var = tk.StringVar(value="off")
        self.count_var = tk.StringVar(value="")
        self._errors = 0
        self._shown = 0
        self._filter_job = None
        self.reader = KlogReader(self._on_line, self._on_state)
        self._build(parent)
        for v in (self.err_only, self.stamp):
            v.trace_add("write", lambda *_: self._redraw())
        self.filter_var.trace_add("write", lambda *_: self._filter_soon())
        self.auto_var.trace_add("write", lambda *_: self._save_opt("klog_auto", self.auto_var.get()))
        self.to_log.trace_add("write", lambda *_: self._save_opt("klog_to_log", self.to_log.get()))
        self.pause.trace_add("write", lambda *_: None if self.pause.get() else self._redraw())
        self.app.root.after(150, self._pump)

    # ------------------------------------------------------------ UI
    def _build(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent, padding=(8, 6, 8, 2))
        bar.pack(fill="x")
        self.btn = ttk.Button(bar, text="Connect", style="Accent.TButton", width=11, command=self.toggle)
        self.btn.pack(side="left")
        self.dot = tk.Label(bar, text="●", fg=theme.c("muted"), bg=theme.c("bg"), font=("Segoe UI", 11))
        self.dot.pack(side="left", padx=(8, 2))
        ttk.Label(bar, textvariable=self.state_var, style="Muted.TLabel").pack(side="left")
        ttk.Checkbutton(bar, text="connect with the console", variable=self.auto_var).pack(side="right")

        bar2 = ttk.Frame(parent, padding=(8, 2))
        bar2.pack(fill="x")
        ttk.Label(bar2, text="Filter").pack(side="left")
        e = ttk.Entry(bar2, textvariable=self.filter_var, width=28)
        e.pack(side="left", padx=4)
        ttk.Label(bar2, text="(text, or /regex/)", style="Muted.TLabel").pack(side="left")
        ttk.Checkbutton(bar2, text="errors only", variable=self.err_only).pack(side="left", padx=(12, 0))
        ttk.Checkbutton(bar2, text="time", variable=self.stamp).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(bar2, text="auto-scroll", variable=self.follow).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(bar2, text="pause", variable=self.pause).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(bar2, text="errors to main log", variable=self.to_log).pack(side="left", padx=(8, 0))
        ttk.Button(bar2, text="Save...", command=self.on_save).pack(side="right", padx=2)
        ttk.Button(bar2, text="Clear", command=self.on_clear).pack(side="right", padx=2)
        ttk.Label(bar2, textvariable=self.count_var, style="Muted.TLabel").pack(side="right", padx=8)

        box = ttk.Frame(parent, padding=(8, 2, 8, 8))
        box.pack(fill="both", expand=True)
        self.text = tk.Text(box, wrap="none", font=theme.mono(10), bg=theme.c("surface"), fg=theme.c("fg"),
                            insertbackground=theme.c("fg"), relief="flat", borderwidth=0, undo=False,
                            selectbackground=theme.c("select"), selectforeground=theme.c("select_fg"))
        ys = ttk.Scrollbar(box, orient="vertical", command=self.text.yview)
        xs = ttk.Scrollbar(box, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        box.grid_rowconfigure(0, weight=1)
        box.grid_columnconfigure(0, weight=1)
        self.text.tag_configure("err", foreground=theme.c("danger"))
        self.text.tag_configure("warn", foreground=theme.c("warn"))
        self.text.tag_configure("ts", foreground=theme.c("muted"))
        # read-only but selectable / copyable
        self.text.bind("<Key>", lambda e: None if e.state & 0x4 else "break")   # Ctrl+C / Ctrl+1.. still work
        self.text.bind("<Control-a>", lambda e: (self.text.tag_add("sel", "1.0", "end"), "break")[1])
        menu = tk.Menu(self.text, tearoff=0)
        menu.add_command(label="Copy", command=lambda: self.text.event_generate("<<Copy>>"))
        menu.add_command(label="Copy all shown", command=self._copy_all)
        menu.add_separator()
        menu.add_command(label="Clear", command=self.on_clear)
        self.text.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))
        ttk.Label(parent, style="Muted.TLabel", padding=(10, 0, 0, 4),
                  text=f"Live /dev/klog from ps5debug-NG (TCP {KLOG_PORT}).  Crashes, page faults and kernel "
                       "errors show here in red - check it when a call or cheat makes the game close.").pack(anchor="w")

    def _save_opt(self, key: str, value) -> None:
        self.app.settings[key] = value          # written to settings.json when the tool closes

    # ------------------------------------------------------------ connection
    def toggle(self) -> None:
        if self.reader.want:
            self.stop()
        else:
            self.start()

    def start(self, host: Optional[str] = None) -> None:
        host = (host or self.app.ip_var.get()).strip()
        if not host:
            self.app.log_line("kernel log: enter the console IP first")
            return
        self.reader.start(host)
        self.btn.configure(text="Disconnect", style="TButton")

    def stop(self) -> None:
        self.reader.stop()
        self.btn.configure(text="Connect", style="Accent.TButton")
        self._set_state("off", "off")

    def on_console_connected(self, host: str) -> None:
        if self.auto_var.get():
            self.start(host)

    # called from the reader thread
    def _on_line(self, text: str) -> None:
        self._q.put(("line", text))

    def _on_state(self, kind: str, msg: str) -> None:
        self._q.put(("state", (kind, msg)))

    def _set_state(self, kind: str, msg: str) -> None:
        self.state_var.set(msg)
        self.dot.configure(fg={"up": theme.c("ok"), "connecting": theme.c("warn"),
                               "down": theme.c("danger")}.get(kind, theme.c("muted")))

    # ------------------------------------------------------------ display
    def _pump(self) -> None:
        new: list[tuple] = []
        try:
            for _ in range(5000):
                kind, data = self._q.get_nowait()
                if kind == "state":
                    if self.reader.want or data[0] == "off":
                        self._set_state(*data)
                    continue
                item = (time.strftime("%H:%M:%S"), data.rstrip(), classify(data))
                self.lines.append(item)
                new.append(item)
                if item[2] == "err":
                    self._errors += 1
                    if self.to_log.get():
                        self.app.log_line(f"klog: {item[1][:300]}")
        except queue.Empty:
            pass
        if new and not self.pause.get():
            self._append(new)
        if new:
            self.count_var.set(f"{len(self.lines)} lines, {self._errors} errors")
        self.app.root.after(150, self._pump)

    def _matcher(self):
        f = self.filter_var.get().strip()
        if not f:
            return None
        if len(f) > 2 and f.startswith("/") and f.endswith("/"):
            try:
                rx = re.compile(f[1:-1], re.I)
                return lambda s: bool(rx.search(s))
            except re.error:
                return lambda s: False
        f = f.lower()
        return lambda s: f in s.lower()

    def _visible(self, items, match) -> list[tuple]:
        eo = self.err_only.get()
        return [it for it in items if (not eo or it[2] == "err") and (match is None or match(it[1]))]

    def _append(self, items) -> None:
        rows = self._visible(items, self._matcher())
        if not rows:
            return
        stamp = self.stamp.get()
        for ts, line, kind in rows:
            if stamp:
                self.text.insert("end", ts + "  ", ("ts",))
            self.text.insert("end", line + "\n", (kind,) if kind else ())
        self._shown += len(rows)
        if self._shown > MAX_SHOW:
            cut = self._shown - MAX_SHOW
            self.text.delete("1.0", f"{cut + 1}.0")
            self._shown = MAX_SHOW
        if self.follow.get():
            self.text.see("end")

    def _redraw(self) -> None:
        self.text.delete("1.0", "end")
        self._shown = 0
        rows = self._visible(self.lines, self._matcher())[-MAX_SHOW:]
        if rows:
            self._append(rows)

    def _filter_soon(self) -> None:
        if self._filter_job:
            self.app.root.after_cancel(self._filter_job)
        self._filter_job = self.app.root.after(250, self._redraw)

    # ------------------------------------------------------------ actions
    def on_clear(self) -> None:
        self.lines.clear()
        self._errors = 0
        self.text.delete("1.0", "end")
        self._shown = 0
        self.count_var.set("")

    def _copy_all(self) -> None:
        self.parent.clipboard_clear()
        self.parent.clipboard_append(self.text.get("1.0", "end-1c"))

    def on_save(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save kernel log", defaultextension=".txt",
            initialfile=time.strftime("klog_%Y-%m-%d_%H%M%S.txt"),
            filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                for ts, line, _k in self.lines:
                    fh.write(f"{ts}  {line}\n")
            self.app.log_line(f"kernel log saved: {path} ({len(self.lines)} lines)")
        except OSError as exc:
            self.app._fail(exc)

    def close(self) -> None:
        self.reader.stop()
