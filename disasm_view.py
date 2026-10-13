"""Instruction list widget used by the Disassembler and Debugger tabs."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Iterable, Optional

from disasm import Insn, K_CALL, K_JCC, K_JMP, K_RET
import theme  # noqa: E402

MenuItems = Callable[[Insn], list]  # [(label, callback) | None for a separator]


class DisasmView(ttk.Frame):
    def __init__(
        self,
        parent,
        on_follow: Optional[Callable[[Insn], None]] = None,
        menu_items: Optional[MenuItems] = None,
        on_toggle_bp: Optional[Callable[[Insn], None]] = None,
        on_select: Optional[Callable[[Optional[Insn]], None]] = None,
        height: int = 20,
    ) -> None:
        super().__init__(parent)
        self.on_follow = on_follow
        self.menu_items = menu_items
        self.on_toggle_bp = on_toggle_bp
        self.on_select = on_select
        self.insns: list[Insn] = []
        self._by_iid: dict[str, Insn] = {}
        self._rip: Optional[int] = None
        self._bps: set[int] = set()

        style = ttk.Style(self)
        style.configure("Disasm.Treeview", font=("Consolas", 10), rowheight=19)

        cols = ("mark", "addr", "bytes", "text", "note")
        self.tree = ttk.Treeview(
            self, columns=cols, show="headings", selectmode="browse", height=height,
            style="Disasm.Treeview",
        )
        for col, title, width, stretch in (
            ("mark", "", 26, False),
            ("addr", "Address", 140, False),
            ("bytes", "Bytes", 190, False),
            ("text", "Instruction", 320, True),
            ("note", "", 150, False),
        ):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=20, stretch=stretch, anchor="w")
        ys = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # one background tag (status) + one foreground tag (instruction kind) per row,
        # so tags never fight over the same option
        self.tree.tag_configure("rip", background=theme.c("hl_rip"))
        self.tree.tag_configure("bp", background=theme.c("hl_bp"))
        self.tree.tag_configure("ripbp", background=theme.c("hl_ripbp"))
        self.tree.tag_configure("call", foreground=theme.c("call"))
        self.tree.tag_configure("ret", foreground=theme.c("danger"))
        self.tree.tag_configure("jmp", foreground=theme.c("jmp"))
        self.tree.tag_configure("jcc", foreground=theme.c("jcc"))

        self.tree.bind("<Double-1>", self._on_double)
        self.tree.bind("<Return>", lambda e: self._follow())
        self.tree.bind("<F9>", lambda e: self._toggle_bp())
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.on_select and self.on_select(self.selected()))
        self.tree.bind("<Control-c>", lambda e: self.copy_selected("line"))

    # ------------------------------------------------------------ content
    @staticmethod
    def _iid(addr: int) -> str:
        return f"{addr:X}"

    def _tags(self, ins: Insn) -> tuple:
        is_rip = ins.addr == self._rip
        is_bp = ins.addr in self._bps
        status = "ripbp" if (is_rip and is_bp) else "rip" if is_rip else "bp" if is_bp else ""
        kind = ("call" if ins.kind & K_CALL else "ret" if ins.kind & K_RET
                else "jmp" if ins.kind & K_JMP else "jcc" if ins.kind & K_JCC else "")
        return tuple(t for t in (status, kind) if t)

    def _mark(self, ins: Insn) -> str:
        if ins.addr == self._rip:
            return "\u25b6"
        return "\u25cf" if ins.addr in self._bps else ""

    def load(
        self,
        insns: Iterable[Insn],
        rip: Optional[int] = None,
        bps: Iterable[int] = (),
        select: Optional[int] = None,
    ) -> None:
        self.insns = list(insns)
        self._rip = rip
        self._bps = set(bps)
        self._by_iid.clear()
        self.tree.delete(*self.tree.get_children())
        for ins in self.insns:
            iid = self._iid(ins.addr)
            self._by_iid[iid] = ins
            self.tree.insert(
                "", "end", iid=iid,
                values=(self._mark(ins), f"{ins.addr:016X}", ins.hexbytes(), ins.text, ins.note()),
                tags=self._tags(ins),
            )
        target = select if select is not None else rip
        if target is not None:
            self.select(target)
        elif self.tree.get_children():
            self.tree.yview_moveto(0)

    def refresh_marks(self, rip: Optional[int], bps: Iterable[int]) -> None:
        """Re-colour rows without reloading (after a breakpoint toggle)."""
        self._rip = rip
        self._bps = set(bps)
        for iid, ins in self._by_iid.items():
            self.tree.item(iid, tags=self._tags(ins))
            self.tree.set(iid, "mark", self._mark(ins))

    def select(self, addr: int) -> bool:
        iid = self._iid(addr)
        if iid in self._by_iid:
            self.tree.selection_set(iid)
            self.tree.focus(iid)
            self._show_with_context(iid)
            return True
        return False

    def _show_with_context(self, iid: str) -> None:
        """Scroll so the row sits about a third of the way down: the code leading up to it stays visible."""
        rows = self.tree.get_children()
        try:
            idx = rows.index(iid)
        except ValueError:
            return
        self.tree.update_idletasks()
        first = self.tree.bbox(rows[0]) if rows else None
        row_h = (first[3] if first else 0) or 17
        visible = max(1, (self.tree.winfo_height() - row_h) // row_h)
        top = max(0, idx - visible // 3)
        if len(rows) > visible:
            self.tree.yview_moveto(top / len(rows))
        self.tree.see(iid)

    def has(self, addr: int) -> bool:
        return self._iid(addr) in self._by_iid

    def selected(self) -> Optional[Insn]:
        sel = self.tree.selection()
        return self._by_iid.get(sel[0]) if sel else None

    def next_address(self) -> Optional[int]:
        return self.insns[-1].addr + self.insns[-1].size if self.insns else None

    # ------------------------------------------------------------ actions
    def _on_double(self, event) -> None:
        row = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not row:
            return
        self.tree.selection_set(row)
        if col == "#1":  # the marker column toggles a breakpoint
            self._toggle_bp()
        else:
            self._follow()

    def _follow(self) -> None:
        ins = self.selected()
        if ins and self.on_follow:
            self.on_follow(ins)

    def _toggle_bp(self) -> None:
        ins = self.selected()
        if ins and self.on_toggle_bp:
            self.on_toggle_bp(ins)

    def _on_right_click(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
        ins = self.selected()
        if not ins:
            return
        menu = tk.Menu(self, tearoff=0)
        items = list(self.menu_items(ins)) if self.menu_items else []
        if items:
            for it in items:
                if it is None:
                    menu.add_separator()
                else:
                    menu.add_command(label=it[0], command=it[1])
            menu.add_separator()
        menu.add_command(label="Copy address", command=lambda: self.copy_selected("addr"))
        menu.add_command(label="Copy bytes", command=lambda: self.copy_selected("bytes"))
        menu.add_command(label="Copy line", command=lambda: self.copy_selected("line"))
        menu.add_command(label="Copy all lines", command=lambda: self.copy_selected("all"))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_selected(self, what: str) -> str:
        ins = self.selected()
        if what == "all":
            text = "\n".join(f"{i.addr:016X}  {i.hexbytes():<30} {i.text}" for i in self.insns)
        elif not ins:
            return "break"
        elif what == "addr":
            text = f"0x{ins.addr:X}"
        elif what == "bytes":
            text = ins.hexbytes()
        else:
            text = f"{ins.addr:016X}  {ins.hexbytes():<30} {ins.text}"
        self.clipboard_clear()
        self.clipboard_append(text)
        return "break"
