"""Disassembler tab: disassemble any address in the target process, follow
branches, patch / NOP / assemble in place, and find references."""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Optional

import asmgen
import codecave
import disasm
from codecave_dialog import CodeCaveDialog, HookState
from debugger_core import label_for
from disasm_view import DisasmView
from disasm import Insn
from scrollable import fit_geometry
import theme  # noqa: E402


class DisassemblerTab:
    def __init__(self, parent: ttk.Frame, app) -> None:
        self.app = app
        self.parent = parent
        self.history: list[int] = []
        self.hpos = -1
        self.patches: list[tuple[int, bytes]] = []  # (address, original bytes) for undo
        self.hooks: dict[int, HookState] = {}       # code caves made this session, by hook address
        self.addr_var = tk.StringVar()
        self.count_var = tk.StringVar(value="128")
        self.info_var = tk.StringVar(
            value="Type an address (0x..., module(eboot.bin)+0x1234, @buf0, rax) and press Go."
        )
        self._build(parent)

    # ----------------------------------------------------------------- UI
    def _build(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent, padding=(8, 8, 8, 4))
        top.pack(fill="x")
        ttk.Label(top, text="Address").pack(side="left")
        entry = ttk.Entry(top, textvariable=self.addr_var, width=42)
        entry.pack(side="left", padx=6)
        entry.bind("<Return>", lambda e: self.on_go())
        ttk.Label(top, text="Instructions").pack(side="left", padx=(8, 2))
        ttk.Combobox(top, textvariable=self.count_var, values=("64", "128", "256", "512"),
                     width=5, state="readonly").pack(side="left")
        ttk.Button(top, text="Go", width=6, command=self.on_go).pack(side="left", padx=8)
        ttk.Button(top, text="\u25c0 Back", command=self.on_back).pack(side="left", padx=2)
        ttk.Button(top, text="Forward \u25b6", command=self.on_forward).pack(side="left", padx=2)
        ttk.Button(top, text="Next page \u25bc", command=self.on_next_page).pack(side="left", padx=2)
        ttk.Button(top, text="Go to RIP", command=self.on_go_rip).pack(side="left", padx=(12, 2))

        # ---- AOB scanner: find code by its bytes (survives game updates, like ShnExt "UniqueAOB")
        ab = ttk.Frame(parent, padding=(8, 0, 8, 4))
        ab.pack(fill="x")
        ttk.Label(ab, text="AOB").pack(side="left")
        self.aob_var = tk.StringVar()
        ae = ttk.Entry(ab, textvariable=self.aob_var, width=58, font=theme.mono())
        ae.pack(side="left", padx=6)
        ae.bind("<Return>", lambda e: self.on_aob_scan())
        self.aob_scope = tk.StringVar(value="Game code")
        ttk.Combobox(ab, textvariable=self.aob_scope, state="readonly", width=16,
                     values=("Game code", "Game code + data", "All modules (code)")).pack(side="left")
        ttk.Button(ab, text="Scan", command=self.on_aob_scan).pack(side="left", padx=(6, 2))
        ttk.Button(ab, text="Make AOB from selected line", command=self.on_aob_make).pack(side="left", padx=2)
        ttk.Button(ab, text="Copy as cheat step", command=self.on_aob_copy_step).pack(side="left", padx=2)
        self.aob_res_var = tk.StringVar()
        self.aob_res = ttk.Combobox(ab, textvariable=self.aob_res_var, state="readonly", width=34)
        self.aob_res.pack(side="left", padx=(8, 0))
        self.aob_res.bind("<<ComboboxSelected>>", lambda e: self._aob_goto())
        self._aob_hits: list[int] = []

        self.view = DisasmView(
            parent,
            on_follow=self._follow,
            menu_items=self._menu,
            on_toggle_bp=self._toggle_bp,
            on_select=self._on_select,
            height=26,
        )
        self.view.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        ttk.Label(parent, textvariable=self.info_var, foreground=theme.c("muted")).pack(
            anchor="w", padx=10, pady=(0, 2)
        )
        ttk.Label(
            parent, foreground=theme.c("muted"),
            text="Double-click a CALL/JMP to follow it (Back returns).  Double-click the first column or press F9 "
                 "for a breakpoint.  Right-click for NOP / patch / assemble here / references.",
        ).pack(anchor="w", padx=10, pady=(0, 6))

    # --------------------------------------------------------- navigation
    def _overrides(self) -> dict[int, int]:
        dbg = getattr(self.app, "debugger", None)
        return dbg.bp_overrides() if dbg else {}

    def on_go(self) -> None:
        text = self.addr_var.get().strip()
        if not text:
            return
        try:
            addr = self.app.eval_full(text)
        except Exception as exc:
            self.app._fail(exc)
            return
        self.goto(addr)

    def goto(self, addr: int, push: bool = True, select: Optional[int] = None) -> None:
        try:
            pid = self.app._pid()
            n = int(self.count_var.get())
        except Exception as exc:
            self.app._fail(exc)
            return
        overrides = self._overrides()

        def work() -> None:
            insns, used_cs = disasm.disassemble(
                self.app.client, pid, addr, min(n * 10, 0x2800), n, overrides
            )
            self.app.root.after(0, lambda: self._show(addr, insns, used_cs, push, select))

        self.app._run_bg(work, "Disassembling...")

    def _show(self, addr: int, insns: list[Insn], used_cs: bool, push: bool, select: Optional[int]) -> None:
        if push:
            del self.history[self.hpos + 1 :]
            self.history.append(addr)
            self.hpos = len(self.history) - 1
        dbg = getattr(self.app, "debugger", None)
        rip = dbg.rip_for_marks() if dbg else None
        bps = dbg.bp_addrs() if dbg else ()
        self.view.load(insns, rip=rip, bps=bps, select=select if select is not None else addr)
        self.addr_var.set(f"0x{addr:X}")
        note = "" if used_cs else "   (capstone not installed - run: pip install capstone  for instruction text)"
        self.info_var.set(f"{len(insns)} instructions from 0x{addr:X}{note}")

    def refresh_marks(self) -> None:
        dbg = getattr(self.app, "debugger", None)
        self.view.refresh_marks(dbg.rip_for_marks() if dbg else None, dbg.bp_addrs() if dbg else ())

    def on_back(self) -> None:
        if self.hpos > 0:
            self.hpos -= 1
            self.goto(self.history[self.hpos], push=False)

    def on_forward(self) -> None:
        if self.hpos + 1 < len(self.history):
            self.hpos += 1
            self.goto(self.history[self.hpos], push=False)

    def on_next_page(self) -> None:
        nxt = self.view.next_address()
        if nxt is not None:
            self.goto(nxt)

    def on_go_rip(self) -> None:
        dbg = getattr(self.app, "debugger", None)
        rip = dbg.rip_for_marks() if dbg else None
        if rip is None:
            self.app.log_line("debugger is not stopped - there is no RIP yet")
            return
        self.goto(rip)

    def _on_select(self, ins: Optional[Insn]) -> None:
        if not ins:
            return
        where = ""
        try:
            maps = getattr(self.app, "_maps_cache", None)
            if maps:
                where = "   " + label_for(maps, ins.addr)
        except Exception:
            pass
        extra = ""
        if ins.target is not None:
            extra = f"   target 0x{ins.target:X}"
        elif ins.ripref is not None:
            extra = f"   rip-relative operand -> 0x{ins.ripref:X}"
        self.info_var.set(f"0x{ins.addr:X}  {ins.size} byte(s){where}{extra}")

    def _follow(self, ins: Insn) -> None:
        if ins.target is not None:
            if self.view.has(ins.target):
                self.view.select(ins.target)
            else:
                self.goto(ins.target)
        elif ins.ripref is not None:
            self.app.log_line(f"data reference 0x{ins.ripref:X} - opening in the hex editor")
            self.app._hex_goto_value(ins.ripref, 0x100)
        else:
            self.app.log_line("this instruction has no direct target to follow")

    def _toggle_bp(self, ins: Insn) -> None:
        dbg = getattr(self.app, "debugger", None)
        if dbg:
            dbg.toggle_bp(ins.addr)

    # ------------------------------------------------------------ AOB
    def _aob_ranges(self, maps):
        import aob as aobmod
        scope = self.aob_scope.get()
        if scope == "All modules (code)":
            return aobmod.regions(maps, "*", code_only=True)
        return aobmod.regions(maps, "main", code_only=(scope == "Game code"))

    def on_aob_scan(self) -> None:
        import aob as aobmod
        try:
            pid = self.app._pid()
            pat, mask = aobmod.parse(self.aob_var.get())
        except Exception as exc:
            self.app._fail(exc)
            return
        app = self.app

        def work() -> None:
            maps = app.client.maps(pid)
            app._maps_cache = maps
            hits = aobmod.find_all(app.client, pid, self._aob_ranges(maps), pat, mask, 64)
            app.root.after(0, lambda: self._aob_show(hits, maps))

        app._run_bg(work, "AOB scan...")

    def _aob_show(self, hits: list[int], maps) -> None:
        self._aob_hits = hits
        vals = [f"{i + 1}: 0x{a:X}  {label_for(maps, a)}" for i, a in enumerate(hits)]
        self.aob_res.configure(values=vals)
        if hits:
            self.aob_res.current(0)
            self._aob_goto()
            more = "  (64+, make it longer)" if len(hits) >= 64 else ""
            self.info_var.set(f"AOB: {len(hits)} match(es){more}" + ("  - unique" if len(hits) == 1 else ""))
        else:
            self.aob_res_var.set("")
            self.info_var.set("AOB: no match")
        self.app.log_line(f"aob scan: {len(hits)} match(es)")

    def _aob_goto(self) -> None:
        i = self.aob_res.current()
        if 0 <= i < len(self._aob_hits):
            self.goto(self._aob_hits[i])

    def on_aob_make(self) -> None:
        """Shortest signature at the selected instruction that is unique in the game code."""
        import aob as aobmod
        ins = self.view.selected()
        if ins is None:
            self.app.log_line("select an instruction first")
            return
        insns = list(self.view.insns)
        start = next(i for i, x in enumerate(insns) if x.addr == ins.addr)
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return
        app = self.app

        def work() -> None:
            maps = app.client.maps(pid)
            text, n = aobmod.unique_signature(app.client, pid, maps, insns, start)

            def ui() -> None:
                self.aob_var.set(text)
                self.aob_scope.set("Game code")
                self._aob_site = ins.addr
                if n == 1:
                    self.info_var.set(f"AOB for 0x{ins.addr:X} is unique ({len(text.split())} bytes) - "
                                      "Copy as cheat step, or tick 'Locate by AOB' in the code cave dialog")
                else:
                    self.info_var.set(f"AOB still matches {n}x after 64 bytes - pick an instruction with more "
                                      "unique code nearby")
            app.root.after(0, ui)

        app._run_bg(work, "Building AOB signature...")

    def on_aob_copy_step(self) -> None:
        import json
        import aob as aobmod
        try:
            pat, mask = aobmod.parse(self.aob_var.get())
        except Exception as exc:
            self.app._fail(exc)
            return
        step = {"op": "aob", "pattern": aobmod.fmt(pat, mask), "store": "site"}
        if self.aob_scope.get() == "Game code + data":
            step["data"] = True
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(json.dumps(step))
        self.app.log_line('copied aob step - it sets $site; use "addr": "$site" in the steps after it')

    # -------------------------------------------------------- context menu
    def _menu(self, ins: Insn) -> list:
        dbg = getattr(self.app, "debugger", None)
        items: list = []
        if ins.target is not None or ins.ripref is not None:
            items.append(("Follow", lambda: self._follow(ins)))
        if dbg:
            items.append(("Toggle breakpoint  (F9)", lambda: dbg.toggle_bp(ins.addr)))
            items.append(("Breakpoint (choose type)...", lambda: dbg.open_bp_dialog(ins.addr, "exec")))
            items.append(("Run to here", lambda: dbg.run_to_cursor(ins.addr)))
        items.append(None)
        items.append(("NOP this instruction", lambda: self._nop(ins)))
        items.append(("Patch bytes...", lambda: self._patch_bytes(ins)))
        items.append(("Assemble here...", lambda: self._assemble_here(ins)))
        if self.patches:
            a, orig = self.patches[-1]
            items.append((f"Undo last patch (0x{a:X}, {len(orig)} bytes)", self._undo_patch))
        items.append(self._cave_menu_item(ins))
        items.append(None)
        items.append(("Make cheat: NOP here → Cheat Editor", lambda: self._make_cheat(ins, "nop")))
        items.append(("Make cheat: patch bytes → Cheat Editor…", lambda: self._make_cheat(ins, "bytes")))
        items.append(("Make cheat: assemble here → Cheat Editor…", lambda: self._make_cheat(ins, "asm")))
        items.append(None)
        items.append(("Log calls to this function (no breakpoint)…", lambda: self.app.open_func_logger(ins.addr)))
        items.append(None)
        items.append(("Find references to this address", lambda: self._find_xrefs(ins.addr)))
        items.append(("Make AOB signature here", lambda: (self.view.select(ins.addr), self.on_aob_make())))
        items.append(("Open in hex editor", lambda: self.app._hex_goto_value(ins.addr, 0x100)))
        return items

    # ----------------------------------------------- make a direct code cheat -> Cheat Editor
    def _make_cheat(self, ins: Insn, kind: str) -> None:
        """Build a patch / asmpatch step for this instruction and send it to the Cheat Editor.
        The address is written as module(name)+0x so the cheat is portable and exports cleanly."""
        editor = getattr(self.app, "cheats_editor", None)
        if editor is None:
            self.app.log_line("the Cheat Editor is not available")
            return
        if kind == "bytes":
            text = simpledialog.askstring("Make cheat: patch bytes",
                                          f"Hex bytes to write at 0x{ins.addr:X}:",
                                          initialvalue=ins.hexbytes(), parent=self.app.root)
            if not text:
                return
            digits = re.sub(r"[^0-9a-fA-F]", "", text)
            if not digits or len(digits) % 2:
                messagebox.showerror("Make cheat", "Enter an even number of hex digits, e.g. 90 90 90")
                return
            payload = bytes.fromhex(digits)
        elif kind == "asm":
            text = simpledialog.askstring(
                "Make cheat: assemble here",
                f"Assembly at 0x{ins.addr:X}  (separate instructions with ; - @buf0 / module(x) allowed):",
                initialvalue=ins.text if ins.text and not ins.text.startswith("(") else "",
                parent=self.app.root)
            if not text:
                return
            payload = text
        else:                                           # nop
            payload = b"\x90" * ins.size

        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return
        addr = ins.addr
        app = self.app

        def work() -> None:
            maps = getattr(app, "_maps_cache", None) or app.client.maps(pid)
            app._maps_cache = maps
            expr = codecave.symbolize(maps, addr)        # module(name)+0x.... or 0x.... if unmapped

            def ui() -> None:
                if kind == "asm":
                    try:
                        data = asmgen.assemble(asmgen.substitute(str(payload).replace(";", "\n"), app.eval_full), addr)
                    except Exception as exc:
                        messagebox.showerror("Make cheat", str(exc))
                        return
                    if len(data) > ins.size and not messagebox.askyesno(
                            "Make cheat", f"The new code is {len(data)} bytes but the instruction is {ins.size}. "
                            f"It will overwrite {len(data) - ins.size} byte(s) of the following instruction(s). "
                            "Add it anyway?"):
                        return
                    step = {"op": "asmpatch", "addr": expr, "asm": str(payload).replace(";", "\n")}
                    label = f"Code {expr}"
                else:
                    step = {"op": "patch", "addr": expr, "type": "hex", "value": payload.hex(" ").upper()}
                    label = ("NOP " if kind == "nop" else "Patch ") + expr
                editor.send_steps([step], suggested_name=label)
            app.root.after(0, ui)

        app._run_bg(work, "Resolving the address...")

    # ----------------------------------------------------------- code cave
    def _cave_menu_item(self, ins: Insn) -> tuple:
        """Right-click entry for code caves; the label says whether it can be done here."""
        hs = self.hooks.get(ins.addr)
        if hs and hs.enabled:
            return ("Code cave (hooked) - edit / disable...", lambda: self._open_cave(ins))
        idx = next((i for i, x in enumerate(self.view.insns) if x.addr == ins.addr), -1)
        dbg = getattr(self.app, "debugger", None)
        bps = dbg.bp_addrs() if dbg else ()
        near = codecave.check_cave(self.view.insns, idx, False, bps)
        if near.ok:
            return ("Code cave...", lambda: self._open_cave(ins))
        far = codecave.check_cave(self.view.insns, idx, True, bps)
        if far.ok:
            return ("Code cave... (needs a far jump)", lambda: self._open_cave(ins))
        return ("Code cave: not possible here (why?)",
                lambda: messagebox.showinfo("Code cave", f"Cannot hook 0x{ins.addr:X}:\n\n{near.reason}"))

    def _open_cave(self, ins: Insn) -> None:
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return
        insns = list(self.view.insns)
        idx = next((i for i, x in enumerate(insns) if x.addr == ins.addr), -1)
        if idx < 0:
            return

        def work() -> None:
            maps = self.app.client.maps(pid)          # for module(name)+offset in the generated code
            self.app._maps_cache = maps
            self.app.root.after(0, lambda: CodeCaveDialog(self, insns, idx))

        self.app._run_bg(work, "Preparing code cave...")

    def refresh_view(self, select: Optional[int] = None) -> None:
        """Re-read the current page (after a hook was enabled/disabled)."""
        top = self._top_addr()
        if top:
            self.goto(top, push=False, select=select)

    # ----------------------------------------------------------- patching
    def _top_addr(self) -> int:
        return self.history[self.hpos] if 0 <= self.hpos < len(self.history) else 0

    def _write(self, addr: int, data: bytes, what: str) -> None:
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return
        top = self._top_addr()

        def work() -> None:
            orig = self.app.client.read(pid, addr, len(data))
            self.app.client.write(pid, addr, data)
            self.patches.append((addr, orig))
            self.app.root.after(0, lambda: self.app.log_line(
                f"{what}: wrote {len(data)} byte(s) at 0x{addr:X}  (was {orig.hex(' ')})"))
            insns, used = disasm.disassemble(self.app.client, pid, top, 0x1000, int(self.count_var.get()),
                                             self._overrides())
            self.app.root.after(0, lambda: self._show(top, insns, used, False, addr))

        self.app._run_bg(work, "Patching...")

    def _nop(self, ins: Insn) -> None:
        if messagebox.askyesno("NOP", f"Overwrite {ins.size} byte(s) at 0x{ins.addr:X} with NOPs?"):
            self._write(ins.addr, b"\x90" * ins.size, "NOP")

    def _patch_bytes(self, ins: Insn) -> None:
        text = simpledialog.askstring(
            "Patch bytes", f"Hex bytes to write at 0x{ins.addr:X}:", initialvalue=ins.hexbytes(),
            parent=self.app.root,
        )
        if not text:
            return
        digits = re.sub(r"[^0-9a-fA-F]", "", text)
        if not digits or len(digits) % 2:
            messagebox.showerror("Patch bytes", "Enter an even number of hex digits, e.g. 90 90 90")
            return
        self._write(ins.addr, bytes.fromhex(digits), "patch")

    def _assemble_here(self, ins: Insn) -> None:
        text = simpledialog.askstring(
            "Assemble here",
            f"Assembly at 0x{ins.addr:X}  (separate instructions with ;  - @buf0 / module(x) allowed):",
            initialvalue=ins.text if ins.text and not ins.text.startswith("(") else "",
            parent=self.app.root,
        )
        if not text:
            return
        try:
            code = asmgen.substitute(text.replace(";", "\n"), self.app.eval_full)
            data = asmgen.assemble(code, ins.addr)
        except Exception as exc:
            messagebox.showerror("Assemble here", str(exc))
            return
        if len(data) > ins.size and not messagebox.askyesno(
            "Assemble here",
            f"The new code is {len(data)} bytes but the instruction is {ins.size}.\n"
            f"It will overwrite {len(data) - ins.size} byte(s) of the following instruction(s). Continue?",
        ):
            return
        if len(data) < ins.size:
            data += b"\x90" * (ins.size - len(data))
        self._write(ins.addr, data, "assemble")

    def _undo_patch(self) -> None:
        if not self.patches:
            return
        addr, orig = self.patches.pop()
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return
        top = self._top_addr()

        def work() -> None:
            self.app.client.write(pid, addr, orig)
            self.app.root.after(0, lambda: self.app.log_line(f"undo: restored {len(orig)} byte(s) at 0x{addr:X}"))
            insns, used = disasm.disassemble(self.app.client, pid, top, 0x1000, int(self.count_var.get()),
                                             self._overrides())
            self.app.root.after(0, lambda: self._show(top, insns, used, False, addr))

        self.app._run_bg(work, "Undoing patch...")

    # --------------------------------------------------------------- xrefs
    def _find_xrefs(self, target: int) -> None:
        try:
            pid = self.app._pid()
        except Exception as exc:
            self.app._fail(exc)
            return

        def work() -> None:
            maps = self.app.client.maps(pid)
            self.app._maps_cache = maps
            home = next((m for m in maps if m.start <= target < m.end), None)
            exec_maps = [m for m in maps if m.prot & 4]
            if home is not None:
                same = [m for m in exec_maps if m.name == home.name]
                exec_maps = same or exec_maps
            hits: list[int] = []
            for m in exec_maps:
                hits.extend(self.app.client.find_xrefs_to(pid, m.start, min(m.end - m.start, 0x20000000), target))
            hits = sorted(set(hits))[:5000]
            self.app.root.after(0, lambda: self._show_xrefs(target, hits, maps))

        self.app._run_bg(work, "Searching references...")

    def _show_xrefs(self, target: int, hits: list[int], maps) -> None:
        win = tk.Toplevel(self.app.root)
        win.title(f"References to 0x{target:X}")
        fit_geometry(win, 560, 380)
        ttk.Label(
            win, padding=8, wraplength=520,
            text=f"{len(hits)} instruction(s) with a RIP-relative operand pointing at 0x{target:X} "
                 "(found by the console's built-in decoder). Double-click to open.",
        ).pack(anchor="w")
        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        lb = tk.Listbox(frame, font=("Consolas", 10), activestyle="none")
        sb = ttk.Scrollbar(frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        lb.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for h in hits:
            lb.insert("end", f"0x{h:016X}   {label_for(maps, h)}")

        def go(_e=None) -> None:
            sel = lb.curselection()
            if sel:
                self.goto(hits[sel[0]])

        lb.bind("<Double-1>", go)
