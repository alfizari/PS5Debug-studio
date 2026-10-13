"""A frame whose content scrolls, with scrollbars and mouse-wheel support."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class ScrollFrame(ttk.Frame):
    """Use `.body` as the parent for your widgets; the frame scrolls around them."""

    def __init__(self, parent, horizontal: bool = True, min_height: int = 0, min_width: int = 0, **kw) -> None:
        """min_height / min_width: the content fills the visible area like a normal frame, but never
        gets smaller than this - below it, scrollbars appear instead of widgets being cut off."""
        super().__init__(parent, **kw)
        self.min_height, self.min_width = min_height, min_width
        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.vbar.grid(row=0, column=1, sticky="ns")
        if horizontal:
            self.hbar = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
            self.canvas.configure(xscrollcommand=self.hbar.set)
            self.hbar.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.body = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._on_body_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        # one global wheel binding per toplevel; each event scrolls the ScrollFrame under the mouse
        top = self.winfo_toplevel()
        if not getattr(top, "_scrollframe_wheel", False):
            top._scrollframe_wheel = True
            for seq in ("<MouseWheel>", "<Shift-MouseWheel>", "<Button-4>", "<Button-5>"):
                top.bind_all(seq, ScrollFrame._dispatch_wheel, add="+")

    def _on_body_configure(self, _e=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event) -> None:
        w = max(event.width, self.min_width or self.body.winfo_reqwidth())
        if self.min_height:
            self.canvas.itemconfigure(self._win, width=w, height=max(event.height, self.min_height))
        else:
            self.canvas.itemconfigure(self._win, width=w)

    @staticmethod
    def _dispatch_wheel(event) -> None:
        w = event.widget
        if isinstance(w, str):
            return
        # widgets that scroll themselves (text, lists, trees, combobox popups) keep the wheel
        try:
            if w.winfo_class() in ("Text", "Treeview", "Listbox"):
                return
        except tk.TclError:
            return
        while w is not None:
            if isinstance(w, ScrollFrame):
                if getattr(event, "state", 0) & 0x1 and hasattr(w, "hbar"):
                    w._on_wheel_h(event)
                else:
                    w._on_wheel(event)
                return
            w = getattr(w, "master", None)

    def _on_wheel(self, event) -> None:
        if max(self.body.winfo_reqheight(), self.body.winfo_height()) <= self.canvas.winfo_height():
            return
        if getattr(event, "num", None) == 4:
            self.canvas.yview_scroll(-3, "units")
        elif getattr(event, "num", None) == 5:
            self.canvas.yview_scroll(3, "units")
        else:
            self.canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

    def _on_wheel_h(self, event) -> None:
        self.canvas.xview_scroll(-1 if event.delta > 0 else 1, "units")


def fit_geometry(win, width: int, height: int) -> None:
    """Size a window to width x height, but never larger than the screen (small laptops, display
    scaling) and never smaller than its content needs, as far as the screen allows."""
    def screen() -> tuple[int, int]:
        return max(320, win.winfo_screenwidth() - 40), max(240, win.winfo_screenheight() - 90)

    sw, sh = screen()
    win.geometry(f"{min(width, sw)}x{min(height, sh)}")

    def grow() -> None:
        try:
            win.update_idletasks()
            rw, rh = win.winfo_reqwidth(), win.winfo_reqheight()
            w, h = min(max(width, rw), sw), min(max(height, rh), sh)
            win.geometry(f"{w}x{h}")
        except Exception:
            pass
    win.after_idle(grow)
