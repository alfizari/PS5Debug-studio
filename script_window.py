"""Python script window: write, run and stop scripts that use the `ps5` API (script_api.py),
and save them into cheats as {"op": "python"} steps."""

from __future__ import annotations

import queue
import re
import threading
import time
import tkinter as tk
from pathlib import Path

from app_paths import APP_DIR
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Callable, Optional

import script_api
import theme

EXAMPLE = '''# ps5 = the running game (see the API list on the right).  F5 runs, Esc stops.
base = ps5.module()                       # eboot.bin
ps5.log("game base", base)

# follow a pointer chain and change a value
# hp = ps5.pointer(base + 0x4A1C00, 0x20, 0x1C4)
# ps5.write_u32(hp, 999, undo=True)

# find code by AOB, allocate a buffer, call a game function
# site = ps5.aob("48 8B 05 ?? ?? ?? ?? 8B 40 1C")
# buf = ps5.alloc("stats", 64, init=bytes([99]) * 64)
# ps5.call(base + 0x123450, buf, 64)
'''

_KW = re.compile(r"\b(def|return|if|elif|else|for|while|in|not|and|or|import|from|as|try|except|finally|"
                 r"with|lambda|True|False|None|break|continue|pass|raise|class|global|is)\b")
_STR = re.compile(r"(\"[^\"\n]*\"|'[^'\n]*')")
_COM = re.compile(r"#[^\n]*")
_API = re.compile(r"\b(ps5|game)\.\w+")


class ScriptWindow:
    _instance: Optional["ScriptWindow"] = None

    @classmethod
    def open(cls, app, code: Optional[str] = None, on_save: Optional[Callable[[str], None]] = None,
             title: str = "") -> "ScriptWindow":
        w = cls._instance
        if w is None or not w.win.winfo_exists():
            w = cls._instance = cls(app)
        w.win.deiconify()
        w.win.lift()
        if code is not None:
            w.set_code(code, on_save, title)
        return w

    def __init__(self, app) -> None:
        self.app, self.root = app, app.root
        self._q: "queue.Queue" = queue.Queue()
        self._stop = threading.Event()
        self._running = False
        self.undo: list = []                       # patches made by scripts run here
        self.on_save: Optional[Callable[[str], None]] = None
        self.path: Optional[Path] = None
        self._hl_job = None
        self.status = tk.StringVar(value="ready")
        self.bound = tk.StringVar(value="")
        self._build()
        self.set_code(app.settings.get("script_last", EXAMPLE), None, "")
        self.root.after(80, self._pump)

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        w = self.win = tk.Toplevel(self.root)
        w.title("Python script")
        w.geometry(self.app.settings.get("script_geom", "1280x720"))
        w.configure(bg=theme.c("bg"))
        w.protocol("WM_DELETE_WINDOW", self.close)
        f = ttk.Frame(w, padding=8)
        f.pack(fill="both", expand=True)

        bar = ttk.Frame(f)
        bar.pack(fill="x")
        self.run_btn = ttk.Button(bar, text="▶ Run  (F5)", style="Accent.TButton", command=self.on_run)
        self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="■ Stop  (Esc)", command=self.on_stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(bar, text="Undo script patches", command=self.on_undo).pack(side="left", padx=(12, 0))
        ttk.Label(bar, textvariable=self.status, style="Muted.TLabel").pack(side="left", padx=12)
        for text, cmd in (("Save into cheat…", self.on_save_cheat), ("Save .py…", self.on_save_file),
                          ("Open .py…", self.on_open_file), ("New", self.on_new)):
            ttk.Button(bar, text=text, style="Small.TButton", command=cmd).pack(side="right", padx=(4, 0))
        ttk.Label(f, textvariable=self.bound, foreground=theme.c("accent")).pack(anchor="w", pady=(4, 0))

        pw = tk.PanedWindow(f, orient="horizontal", sashwidth=6, bd=0, bg=theme.c("bg"))
        pw.pack(fill="both", expand=True, pady=(4, 0))
        left = tk.PanedWindow(pw, orient="vertical", sashwidth=6, bd=0, bg=theme.c("bg"))
        ed = ttk.Frame(left)
        self.lines = tk.Text(ed, width=4, font=theme.mono(10), bg=theme.c("surface2"), fg=theme.c("muted"),
                             relief="flat", state="disabled", takefocus=0)
        self.lines.pack(side="left", fill="y")
        self.text = tk.Text(ed, font=theme.mono(10), undo=True, wrap="none", bg=theme.c("surface"),
                            fg=theme.c("fg"), insertbackground=theme.c("fg"), relief="flat", tabs=("4c",))
        ys = ttk.Scrollbar(ed, orient="vertical", command=self._yview)
        self.text.configure(yscrollcommand=lambda a, b: (ys.set(a, b), self.lines.yview_moveto(a)))
        self.text.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.text.tag_configure("kw", foreground=theme.c("jmp"))
        self.text.tag_configure("str", foreground=theme.c("ok"))
        self.text.tag_configure("com", foreground=theme.c("muted"))
        self.text.tag_configure("api", foreground=theme.c("call"))
        self.text.tag_configure("errline", background=theme.c("hl_bp"))
        self.text.bind("<<Modified>>", self._modified)
        self.text.bind("<Tab>", lambda e: (self.text.insert("insert", "    "), "break")[1])
        self.text.bind("<Return>", self._newline)
        for key in ("<F5>", "<Control-Return>"):
            w.bind(key, lambda e: (self.on_run(), "break")[1])
        w.bind("<Escape>", lambda e: self.on_stop())
        w.bind("<Control-s>", lambda e: (self.on_save_cheat() if self.on_save else self.on_save_file(), "break")[1])
        left.add(ed, stretch="always", minsize=200)
        of = ttk.Frame(left)
        ttk.Label(of, text="Output", style="Title.TLabel").pack(anchor="w")
        self.out = tk.Text(of, height=9, font=theme.mono(9), bg=theme.c("surface2"), fg=theme.c("fg"),
                           relief="flat", wrap="word")
        self.out.pack(fill="both", expand=True)
        self.out.tag_configure("err", foreground=theme.c("danger"))
        self.out.tag_configure("dim", foreground=theme.c("muted"))
        left.add(of, minsize=80)
        pw.add(left, stretch="always", minsize=500)

        right = ttk.Frame(pw)
        ttk.Label(right, text="ps5 API  (double-click a line to insert it)", style="Title.TLabel").pack(anchor="w")
        self.help = tk.Text(right, width=60, font=theme.mono(9), bg=theme.c("surface2"), fg=theme.c("fg"),
                            relief="flat", wrap="none", cursor="hand2")
        self.help.insert("1.0", script_api.API_HELP)
        self.help.tag_configure("head", foreground=theme.c("accent"), font=theme.mono(9, "bold"))
        for i, ln in enumerate(script_api.API_HELP.split("\n"), 1):
            if ln and ln.upper() == ln and not ln.startswith(" "):
                self.help.tag_add("head", f"{i}.0", f"{i}.end")
        self.help.configure(state="disabled")
        self.help.pack(fill="both", expand=True)
        self.help.bind("<Double-1>", self._insert_help)
        pw.add(right, minsize=420)

    def _yview(self, *a) -> None:
        self.text.yview(*a)
        self.lines.yview(*a)

    def _newline(self, _e=None) -> str:
        line = self.text.get("insert linestart", "insert")
        indent = re.match(r"\s*", line).group(0)
        if line.rstrip().endswith(":"):
            indent += "    "
        self.text.insert("insert", "\n" + indent)
        self.text.see("insert")
        return "break"

    def _insert_help(self, event) -> str:
        line = self.help.get(f"@{event.x},{event.y} linestart", f"@{event.x},{event.y} lineend")
        col = self.help.index(f"@{event.x},{event.y}").split(".")[1]
        # the call under the mouse (lines hold two or three entries)
        parts = [(m.start(), m.group(0)) for m in re.finditer(r"ps5\.\w+(?:\([^)]*\))?(?:\[[^\]]*\])?", line)]
        pick = next((t for s, t in reversed(parts) if s <= int(col)), parts[0][1] if parts else "")
        if pick:
            self.text.insert("insert", pick)
            self.text.focus_set()
        return "break"

    def _modified(self, _e=None) -> None:
        if not self.text.edit_modified():
            return
        self.text.edit_modified(False)
        if self._hl_job:
            self.root.after_cancel(self._hl_job)
        self._hl_job = self.root.after(200, self._highlight)

    def _highlight(self) -> None:
        self._hl_job = None
        src = self.text.get("1.0", "end-1c")
        for tag in ("kw", "str", "com", "api"):
            self.text.tag_remove(tag, "1.0", "end")
        for rx, tag in ((_KW, "kw"), (_API, "api"), (_STR, "str"), (_COM, "com")):
            for m in rx.finditer(src):
                self.text.tag_add(tag, f"1.0+{m.start()}c", f"1.0+{m.end()}c")
        n = src.count("\n") + 1
        self.lines.configure(state="normal")
        self.lines.delete("1.0", "end")
        self.lines.insert("1.0", "\n".join(str(i) for i in range(1, n + 1)))
        self.lines.configure(state="disabled")
        self.lines.yview_moveto(self.text.yview()[0])

    def set_code(self, code: str, on_save: Optional[Callable[[str], None]], title: str) -> None:
        self.text.delete("1.0", "end")
        self.text.insert("1.0", code)
        self.text.edit_reset()
        self.on_save = on_save
        self.bound.set(f"Editing: {title}   (Save into cheat / Ctrl+S writes it back)" if on_save else "")
        self._highlight()

    # ------------------------------------------------------------------ output
    def _post(self, fn) -> None:
        self._q.put(fn)

    def _pump(self) -> None:
        try:
            for _ in range(200):
                self._q.get_nowait()()
        except queue.Empty:
            pass
        if self.win.winfo_exists():
            self.root.after(60, self._pump)

    def write(self, text: str, tag: str = "") -> None:
        def ui() -> None:
            self.out.insert("end", text + "\n", (tag,) if tag else ())
            if int(self.out.index("end-1c").split(".")[0]) > 3000:
                self.out.delete("1.0", "500.0")
            self.out.see("end")
        self._post(ui)

    # ------------------------------------------------------------------ run
    def on_run(self) -> None:
        if self._running:
            return
        code = self.text.get("1.0", "end-1c")
        self.app.settings["script_last"] = code
        try:
            pid = self.app._pid()
        except Exception:
            messagebox.showerror("Python script", "Pick the game process (PID) first.", parent=self.win)
            return
        if not self.app.client.connected:
            messagebox.showerror("Python script", "Connect to the console first.", parent=self.win)
            return
        import cheats   # noqa: PLC0415
        self._stop.clear()
        self._running = True
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.text.tag_remove("errline", "1.0", "end")
        self.status.set("running…")
        self.write(f"--- run {time.strftime('%H:%M:%S')} ---", "dim")
        rt = cheats.Runtime(self.app.client, self.app.state, pid, self.app.make_cheat_buffer,
                            lambda m: self.write(m.strip(), "dim"), self.undo)
        rt.stop_event = self._stop
        t0 = time.monotonic()

        def work() -> None:
            err = None
            try:
                script_api.run_code(code, rt, self.write, self._stop)
            except script_api.ScriptStopped:
                err = "stopped"
            except Exception as exc:
                err = str(exc)
            dt = time.monotonic() - t0
            self._post(lambda: self._done(err, dt))
        threading.Thread(target=work, daemon=True).start()

    def _done(self, err: Optional[str], dt: float) -> None:
        self._running = False
        self.run_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if err and err != "stopped":
            self.out.insert("end", err + "\n", ("err",))
            self.out.see("end")
            m = re.search(r"script line (\d+)", err)
            if m:
                ln = int(m.group(1))
                self.text.tag_add("errline", f"{ln}.0", f"{ln}.end+1c")
                self.text.see(f"{ln}.0")
            self.status.set(f"error after {dt:.1f}s")
        else:
            self.status.set(f"{'stopped' if err else 'done'} in {dt:.1f}s" +
                            (f"  ·  {len(self.undo)} patch(es) can be undone" if self.undo else ""))
        self.app._refresh_buffers() if hasattr(self.app, "_refresh_buffers") else None

    def on_stop(self) -> None:
        if self._running:
            self._stop.set()
            self.status.set("stopping… (at the next ps5 call)")

    def on_undo(self) -> None:
        if not self.undo:
            self.status.set("no script patches to undo")
            return
        if self._running:
            self.status.set("stop the script first")
            return
        try:
            pid = self.app._pid()
            n = len(self.undo)
            while self.undo:
                a, orig = self.undo.pop()
                self.app.client.write(pid, a, orig)
            self.status.set(f"restored {n} patch(es)")
        except Exception as exc:
            self.status.set(f"undo failed: {exc}")

    # ------------------------------------------------------------------ files / cheats
    def _scripts_dir(self) -> Path:
        d = APP_DIR / "scripts"
        d.mkdir(exist_ok=True)
        return d

    def on_new(self) -> None:
        self.set_code(EXAMPLE, None, "")
        self.path = None

    def on_open_file(self) -> None:
        p = filedialog.askopenfilename(parent=self.win, initialdir=str(self._scripts_dir()),
                                       filetypes=[("Python", "*.py"), ("All", "*.*")])
        if p:
            self.path = Path(p)
            self.set_code(self.path.read_text(encoding="utf-8"), None, "")
            self.status.set(f"opened {self.path.name}")

    def on_save_file(self) -> None:
        p = filedialog.asksaveasfilename(parent=self.win, initialdir=str(self._scripts_dir()),
                                         initialfile=self.path.name if self.path else "script.py",
                                         defaultextension=".py", filetypes=[("Python", "*.py")])
        if p:
            self.path = Path(p)
            self.path.write_text(self.text.get("1.0", "end-1c"), encoding="utf-8")
            self.status.set(f"saved {self.path.name}")

    def on_save_cheat(self) -> None:
        code = self.text.get("1.0", "end-1c")
        if self.on_save:
            self.on_save(code)
            self.status.set("saved into the cheat")
            return
        ed = getattr(self.app, "cheats_editor", None)
        if ed is None:
            return
        name = simpledialog.askstring("Save into cheat", "New cheat name (it is added to the game selected "
                                      "in the Cheat Editor):", parent=self.win)
        if not name:
            return
        mode = "toggle" if messagebox.askyesno(
            "Save into cheat", "Make it an ON/OFF (toggle) cheat?\n\nYes: patches made with ps5.patch / "
            "write_..(undo=True) are restored when it is turned off.\nNo: it runs once per click.",
            parent=self.win) else "once"
        err = ed.add_python_cheat(name, code, mode)
        if err:
            messagebox.showerror("Save into cheat", err, parent=self.win)
        else:
            self.status.set(f"saved as cheat '{name}'")

    def close(self) -> None:
        self._stop.set()
        try:
            self.app.settings["script_geom"] = self.win.geometry()
            self.app.settings["script_last"] = self.text.get("1.0", "end-1c")
        except tk.TclError:
            pass
        self.win.withdraw()                      # keep the text: reopening shows it again
