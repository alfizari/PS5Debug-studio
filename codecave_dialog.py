"""Code cave dialog (opened from the Disassembler's right-click menu).

Shows the instruction(s) being replaced as editable assembly, lets you
preview / enable / disable the hook (disable restores the original bytes),
and add the hook to the cheat system: as a step in the Cheat Editor, or as a
brand-new cheat.  All the real work is the `hook` step in cheats.py, so
the dialog and a saved cheat behave identically.
"""

from __future__ import annotations

import re
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import messagebox, ttk
from typing import Optional

import codecave
import disasm
from cheats import Cheat, Game, Runtime
from scrollable import fit_geometry
import theme  # noqa: E402


@dataclass
class HookState:
    """Per-session memory of one hook, kept by the Disassembler tab."""
    addr: int
    orig: bytes
    far: bool
    asm: str
    name: str
    enabled: bool = False
    cave: int = 0
    undo: list = field(default_factory=list)


class CodeCaveDialog:
    HELP = (
        "Left: what the game runs at the hook address today.  Edit it or add lines - this code runs INSTEAD, then the "
        "game continues after the replaced instructions (a jump back is appended for you).\n"
        "Expressions work as in cheats: @buf0   $input   module(eboot.bin)+0x10   {expr}.   "
        "[rip:EXPR] = RIP-relative operand to an absolute address (written for you, stays ASLR-safe).\n"
        "Registers/flags you change here are visible to the game afterwards - save and restore what you use "
        "(push/pop) unless you mean to change it."
    )

    def __init__(self, tab, insns: list, index: int) -> None:
        self.tab = tab
        self.app = tab.app
        self.insns = insns
        self.index = index
        self.addr = insns[index].addr
        self.hs: Optional[HookState] = tab.hooks.get(self.addr)
        self.chk: Optional[codecave.CaveCheck] = None
        self.orig = self.hs.orig if self.hs else b""
        self.stale = bool(self.hs and self.hs.enabled)   # opened while hooked: the view shows the jump, not the original
        self._generated = ""
        maps = getattr(self.app, "_maps_cache", None) or []
        self.maps = maps
        self.sym = codecave.symbolize(maps, self.addr)

        win = tk.Toplevel(self.app.root)
        self.win = win
        win.title(f"Code cave  -  {self.sym}")
        fit_geometry(win, 900, 700)
        win.transient(self.app.root)

        self.info_var = tk.StringVar()
        self.status_var = tk.StringVar()
        ttk.Label(win, textvariable=self.info_var, font=("Segoe UI", 10, "bold"), padding=(8, 8, 8, 0)).pack(anchor="w")
        self.status_lbl = ttk.Label(win, textvariable=self.status_var, padding=(8, 0, 8, 4))
        self.status_lbl.pack(anchor="w")

        opt = ttk.Frame(win, padding=(8, 0))
        opt.pack(fill="x")
        ttk.Label(opt, text="Name").pack(side="left")
        self.name_var = tk.StringVar(value=self.hs.name if self.hs else f"hook_{self.addr:X}")
        self.name_entry = ttk.Entry(opt, textvariable=self.name_var, width=18)
        self.name_entry.pack(side="left", padx=4)
        self.far = tk.BooleanVar(value=self.hs.far if self.hs else False)
        self.far_cb = ttk.Checkbutton(
            opt, text="Far jump (14 bytes, no distance limit; default is a 5-byte jump to a cave within 2 GB)",
            variable=self.far, command=self._on_far)
        self.far_cb.pack(side="left", padx=12)
        self.use_aob = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="Locate by AOB (instead of a fixed offset)", variable=self.use_aob).pack(
            side="left", padx=4)

        self.warn_var = tk.StringVar()
        ttk.Label(win, textvariable=self.warn_var, foreground=theme.c("danger"), wraplength=860, justify="left",
                  padding=(8, 4)).pack(anchor="w")
        self.note_var = tk.StringVar()
        ttk.Label(win, textvariable=self.note_var, foreground=theme.c("muted"), wraplength=860, justify="left",
                  padding=(8, 0)).pack(anchor="w")
        ttk.Label(win, text=self.HELP, wraplength=860, justify="left", foreground=theme.c("muted"),
                  padding=(8, 0, 8, 4)).pack(anchor="w")

        mid = ttk.Panedwindow(win, orient="vertical")
        mid.pack(fill="both", expand=True, padx=8, pady=4)
        af = ttk.LabelFrame(mid, text="Cave code (x86-64)")
        of = ttk.LabelFrame(mid, text="Preview  (cave code incl. the appended jump back)")
        mid.add(af, weight=3)
        mid.add(of, weight=2)
        self.asm = tk.Text(af, wrap="none", font=("Consolas", 11), undo=True, height=12)
        ys = ttk.Scrollbar(af, orient="vertical", command=self.asm.yview)
        self.asm.configure(yscrollcommand=ys.set)
        self.asm.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.out = tk.Text(of, wrap="none", font=("Consolas", 10), height=8, state="disabled")
        oys = ttk.Scrollbar(of, orient="vertical", command=self.out.yview)
        self.out.configure(yscrollcommand=oys.set)
        self.out.pack(side="left", fill="both", expand=True)
        oys.pack(side="right", fill="y")
        self.out.tag_configure("err", foreground=theme.c("danger"))

        # button rows are packed at the bottom ahead of the editors, so on a small screen the
        # editors shrink and the buttons stay visible
        b1 = ttk.Frame(win, padding=(8, 4))
        b1.pack(side="bottom", fill="x", before=mid)
        ttk.Button(b1, text="Assemble preview", command=self.on_preview).pack(side="left", padx=2)
        self.btn_enable = ttk.Button(b1, text="Enable hook", command=self.on_enable)
        self.btn_enable.pack(side="left", padx=2)
        self.btn_disable = ttk.Button(b1, text="Disable (restore original)", command=self.on_disable)
        self.btn_disable.pack(side="left", padx=2)
        ttk.Button(b1, text="Reset to original instructions", command=self.on_reset).pack(side="left", padx=10)
        b2 = ttk.Frame(win, padding=(8, 0, 8, 8))
        b2.pack(side="bottom", fill="x", before=b1)
        ttk.Button(b2, text="Insert step into Cheat Editor", command=self.on_insert_step).pack(side="left", padx=2)
        ttk.Button(b2, text="Save as new cheat...", command=self.on_save_cheat).pack(side="left", padx=2)
        ttk.Button(b2, text="Close", command=win.destroy).pack(side="right", padx=2)

        if self.hs and self.hs.enabled:
            self.asm.insert("1.0", self.hs.asm)
            self._generated = self.hs.asm
        else:
            self._recheck(first=True)
        self._update_status()
        self.on_preview(quiet=True)

    # --------------------------------------------------------------- state
    def _enabled(self) -> bool:
        return bool(self.hs and self.hs.enabled)

    def _bps(self):
        dbg = getattr(self.app, "debugger", None)
        return dbg.bp_addrs() if dbg else ()

    def _recheck(self, first: bool = False) -> None:
        """Work out which instructions are stolen for the current jump type."""
        chk = codecave.check_cave(self.insns, self.index, self.far.get(), self._bps())
        self.chk = chk
        if not chk.ok:
            self.orig = b""
            self.warn_var.set(f"Cannot hook here: {chk.reason}")
            return
        self.orig = chk.orig
        text = codecave.original_text(chk.stolen, self.maps)
        keep = self.hs.asm if (first and self.hs and self.hs.asm) else text
        self.asm.delete("1.0", "end")
        self.asm.insert("1.0", keep)
        self._generated = text
        self.warn_var.set("\n".join(chk.warnings))
        self.note_var.set("\n".join(chk.notes))

    def _on_far(self) -> None:
        if self._enabled() or self.stale:
            self.far.set(self.hs.far if self.hs else self.far.get())
            messagebox.showinfo("Code cave", "Disable the hook, close and re-open this dialog to change the "
                                "jump type.", parent=self.win)
            return
        if self.asm.get("1.0", "end-1c").strip() != self._generated.strip():
            if not messagebox.askyesno("Code cave", "Changing the jump type changes which instructions are "
                                       "replaced and resets the code. Discard your edits?", parent=self.win):
                self.far.set(not self.far.get())
                return
        self._recheck()
        self._update_status()
        self.on_preview(quiet=True)

    def _update_status(self) -> None:
        n = len(self.orig)
        resume = self.addr + n
        count = len(self.chk.stolen) if (self.chk and self.chk.ok) else None
        what = f"{count} instruction(s), {n} bytes" if count else f"{n} bytes"
        self.info_var.set(f"Hook at {self.sym}  (0x{self.addr:X})   -   replaces {what}   -   resumes at 0x{resume:X}"
                          if n else f"Hook at {self.sym}  (0x{self.addr:X})   -   not possible here")
        if self._enabled():
            self.status_var.set(f"ENABLED  -  cave at 0x{self.hs.cave:X}")
            self.status_lbl.configure(foreground=theme.c("ok"))
            self.btn_enable.configure(text="Apply changes", state="normal")
            self.btn_disable.configure(state="normal")
            self.far_cb.configure(state="disabled")
            self.name_entry.configure(state="disabled")
        else:
            self.status_var.set("not hooked (original code is running)")
            self.status_lbl.configure(foreground=theme.c("muted"))
            self.btn_enable.configure(text="Enable hook", state="normal" if n else "disabled")
            self.btn_disable.configure(state="disabled")
            self.far_cb.configure(state="disabled" if self.stale else "normal")
            self.name_entry.configure(state="normal")

    # ------------------------------------------------------------- helpers
    def _asm_text(self) -> str:
        return self.asm.get("1.0", "end-1c")

    def _step(self) -> dict:
        name = self.name_var.get().strip()
        if not re.fullmatch(r"[A-Za-z_][\w.\-]*", name):
            raise ValueError("name: letters, digits, _ . - only (must start with a letter or _)")
        if not self.orig:
            raise ValueError("this location cannot be hooked")
        return codecave.build_step(name, self.sym, self.orig, self._asm_text(), self.far.get())

    def _write_out(self, text: str, error: bool = False) -> None:
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text, ("err",) if error else ())
        self.out.configure(state="disabled")

    # ------------------------------------------------------------- actions
    def on_preview(self, quiet: bool = False) -> None:
        if not self.orig:
            self._write_out(self.warn_var.get() or "nothing to assemble", error=True)
            return
        base = self.hs.cave if (self.hs and self.hs.cave) else self.addr
        try:
            code = codecave.assemble_cave(self._asm_text(), base, self.app.eval_full, self.addr + len(self.orig))
        except Exception as exc:
            self._write_out(str(exc), error=True)
            return
        lines = [f"{len(code)} bytes (shown as if the cave were at 0x{base:X})", ""]
        if disasm.have_capstone():
            for i in disasm.decode(code, base, 200):
                lines.append(f"{i.addr:X}  {i.hexbytes():<30} {i.text}")
        else:
            lines.append(code.hex(" "))
        self._write_out("\n".join(lines))

    def on_reset(self) -> None:
        if self._enabled() or self.stale:
            messagebox.showinfo("Code cave", "Disable the hook, then close and re-open this dialog to reset the "
                                "instructions.", parent=self.win)
            return
        self._recheck()
        self.on_preview(quiet=True)

    def _confirm_risks(self) -> bool:
        if self.chk and self.chk.warnings and not self._enabled():
            return messagebox.askyesno("Code cave", "Risks:\n\n" + "\n".join(self.chk.warnings) + "\n\nEnable anyway?",
                                       parent=self.win)
        return True

    def on_enable(self) -> None:
        app = self.app
        try:
            pid = app._pid()
            step = self._step()
        except Exception as exc:
            messagebox.showerror("Code cave", str(exc), parent=self.win)
            return
        if not self._confirm_risks():
            return
        if not self.hs:
            self.hs = HookState(self.addr, self.orig, self.far.get(), self._asm_text(), step["name"])
            self.tab.hooks[self.addr] = self.hs
        hs = self.hs
        if not hs.enabled:
            hs.orig = self.orig
        hs.far, hs.asm, hs.name = self.far.get(), self._asm_text(), step["name"]
        step["orig"] = hs.orig.hex(" ").upper()
        root = app.root

        def log(m: str) -> None:
            root.after(0, lambda t=m: app.log_line(t))

        def work() -> None:
            rt = Runtime(app.client, app.state, pid, app.make_cheat_buffer, log, hs.undo)
            rt.run([step])
            hs.enabled = True
            hs.cave = next((b.address for b in app.state.buffers if b.name == hs.name), 0)
            root.after(0, self._after_change)

        app._run_bg(work, "Enabling code cave...")

    def on_disable(self) -> None:
        app, hs = self.app, self.hs
        if not hs or not hs.enabled:
            return
        try:
            pid = app._pid()
        except Exception as exc:
            app._fail(exc)
            return
        root = app.root

        def work() -> None:
            while hs.undo:
                a, o = hs.undo.pop()
                app.client.write(pid, a, o)
                root.after(0, lambda a=a, n=len(o): app.log_line(f"  restore 0x{a:X} ({n} bytes)"))
            hs.enabled = False
            root.after(0, self._after_change)

        app._run_bg(work, "Disabling code cave...")

    def _after_change(self) -> None:
        self.app._refresh_buf_tree()
        self.app.log_line(f"code cave {self.sym}: {'ENABLED' if self._enabled() else 'disabled (original restored)'}")
        if not self._enabled():
            self._recheck_after_disable()
        self._update_status()
        self.app.root.after(250, lambda: self.tab.refresh_view(self.addr))

    def _recheck_after_disable(self) -> None:
        self.chk = None
        self.orig = self.hs.orig if self.hs else self.orig
        self.warn_var.set("")

    def _with_steps(self, then) -> None:
        """then(list_of_steps) on the UI thread; with 'Locate by AOB' an `aob` step that finds the
        site by a unique signature comes first and the hook uses "$<name>_site"."""
        try:
            step = self._step()
            pid = self.app._pid() if self.use_aob.get() else 0
        except Exception as exc:
            messagebox.showerror("Code cave", str(exc), parent=self.win)
            return
        if not self.use_aob.get():
            then([step])
            return
        app = self.app
        import aob as aobmod

        def work() -> None:
            maps = app.client.maps(pid)
            text, n = aobmod.unique_signature(app.client, pid, maps, self.insns, self.index)
            if n != 1:
                raise RuntimeError(f"no unique AOB here (best signature still matches {n} places) - "
                                   "untick 'Locate by AOB' or hook a nearby instruction")
            var = re.sub(r"\W", "_", step["name"]) + "_site"
            find = {"op": "aob", "pattern": text, "store": var}
            hook = dict(step, addr=f"${var}")
            app.root.after(0, lambda: then([find, hook]))

        app._run_bg(work, "Building AOB signature...")

    def on_insert_step(self) -> None:
        def done(steps: list) -> None:
            ok = True
            for st in steps:
                ok = ok and self.app.cheats_editor.insert_step(st)
            if ok:
                self.app.notebook.select(self.app._cheats_editor_tab)
                self.app.log_line(f"inserted {len(steps)} step(s) for hook '{steps[-1]['name']}' into the Cheat Editor")
        self._with_steps(done)

    def on_save_cheat(self) -> None:
        self._with_steps(self._save_cheat)

    def _save_cheat(self, steps: list) -> None:
        try:
            pid = self.app._pid()
        except Exception as exc:
            messagebox.showerror("Code cave", str(exc), parent=self.win)
            return
        step = steps
        app = self.app

        def work() -> None:
            tid, pname = "", ""
            try:
                info = app.client.proc_info(pid)
                tid, pname = info.titleid.strip().upper(), info.name
            except Exception:
                pass
            app.root.after(0, lambda: SaveCheatDialog(self, step, tid, pname))

        app._run_bg(work, "Reading title id...")


class SaveCheatDialog:
    NEW = "(new game file)"

    def __init__(self, cave: CodeCaveDialog, step: dict, title_id: str, proc_name: str) -> None:
        self.cave, self.proc_name = cave, proc_name
        self.steps = step if isinstance(step, list) else [step]
        self.step = self.steps[-1]
        self.ed = cave.app.cheats_editor
        win = tk.Toplevel(cave.win)
        self.win = win
        win.title("Save code cave as cheat")
        win.transient(cave.win)
        fit_geometry(win, 520, 330)
        bt = ttk.Frame(win, padding=(10, 0, 10, 10))
        bt.pack(side="bottom", fill="x")             # first, so Save is never cut off
        ttk.Button(bt, text="Save cheat", style="Accent.TButton", command=self.on_save).pack(side="left")
        ttk.Button(bt, text="Cancel", command=win.destroy).pack(side="left", padx=6)
        f = ttk.Frame(win, padding=10)
        f.pack(fill="both", expand=True)
        self.name = tk.StringVar(value=f"Code cave {cave.sym}")
        self.desc = tk.StringVar(value="")
        self.mode = tk.StringVar(value="toggle")
        games = [f"{g.name} [{g.title_id}]" for g in self.ed.games]
        default = self.NEW
        for label, g in zip(games, self.ed.games):
            if title_id and g.title_id == title_id:
                default = label
        self.choice = tk.StringVar(value=default)
        self.gname = tk.StringVar(value=title_id or "New game")
        self.tid = tk.StringVar(value=title_id)

        rows = [("Cheat name", ttk.Entry(f, textvariable=self.name, width=44)),
                ("Description", ttk.Entry(f, textvariable=self.desc, width=44))]
        for r, (lbl, w) in enumerate(rows):
            ttk.Label(f, text=lbl).grid(row=r, column=0, sticky="w", pady=2)
            w.grid(row=r, column=1, sticky="we", pady=2)
        mrow = ttk.Frame(f)
        mrow.grid(row=2, column=1, sticky="w", pady=2)
        ttk.Label(f, text="Mode").grid(row=2, column=0, sticky="w")
        ttk.Radiobutton(mrow, text="toggle (off restores the original)", variable=self.mode, value="toggle").pack(side="left")
        ttk.Radiobutton(mrow, text="once", variable=self.mode, value="once").pack(side="left", padx=8)
        ttk.Label(f, text="Save into").grid(row=3, column=0, sticky="w", pady=2)
        ttk.Combobox(f, textvariable=self.choice, values=[self.NEW] + games, state="readonly", width=42).grid(
            row=3, column=1, sticky="we")
        ttk.Label(f, text="New game name").grid(row=4, column=0, sticky="w", pady=2)
        ttk.Entry(f, textvariable=self.gname, width=44).grid(row=4, column=1, sticky="we")
        ttk.Label(f, text="Title ID").grid(row=5, column=0, sticky="w", pady=2)
        ttk.Entry(f, textvariable=self.tid, width=20).grid(row=5, column=1, sticky="w")
        vars_ = codecave.dollar_vars(str(self.step.get("asm", "")))   # `step` may be [aob, hook]
        if vars_:
            ttk.Label(f, foreground=theme.c("muted"), wraplength=480,
                      text="$" + ", $".join(vars_) + " in the code become inputs on the Cheats tab (u64, default 0).").grid(
                row=6, column=0, columnspan=2, sticky="w", pady=6)
        f.columnconfigure(1, weight=1)

    def on_save(self) -> None:
        name = self.name.get().strip()
        if not name:
            messagebox.showerror("Cheats", "Give the cheat a name", parent=self.win)
            return
        ed = self.ed
        params = [{"name": v, "label": v.replace("_", " ").title(), "type": "u64", "default": "0"}
                  for v in codecave.dollar_vars(self.step["asm"])]
        try:
            if self.choice.get() == self.NEW:
                tid = self.tid.get().strip().upper()
                gname = self.gname.get().strip() or tid or "New game"
                path = ed.folder / f"{re.sub(r'[^A-Za-z0-9_.-]+', '_', tid or gname).strip('_')}.json"
                if path.exists():
                    raise ValueError(f"{path.name} already exists - pick it in 'Save into'")
                game = Game(name=gname, title_id=tid, process=self.proc_name, path=path)
            else:
                labels = [f"{g.name} [{g.title_id}]" for g in ed.games]
                game = ed.games[labels.index(self.choice.get())]
            base, n = name, 1
            while any(c.name == name for c in game.cheats):
                n += 1
                name = f"{base} {n}"
            cheat = Cheat(name=name, description=self.desc.get().strip(), mode=self.mode.get(),
                          steps=list(self.steps), params=params)
            game.cheats.append(cheat)
            game.save()
        except Exception as exc:
            messagebox.showerror("Cheats", str(exc), parent=self.win)
            return
        key = (str(game.path), cheat.name)
        ed.reload()
        ed._fill(select=key)
        self.cave.app.log_line(f"saved code cave cheat '{cheat.name}' into {game.path.name}")
        self.win.destroy()
