"""Clickable 16-byte-row hex editor with selection, copy and dump (stdlib Tk).

Select:  drag with the mouse, Shift+click, Shift+arrows, Ctrl+A.
Copy:    Ctrl+C = hex of the selection (or the byte under the cursor),
         Ctrl+Shift+C = cursor address, right-click / Copy menu = more formats.
Dump:    "Save to file..." writes the selection (or the whole view if nothing
         is selected) as raw bytes (.bin) or as a text hex dump (.txt).
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional
import theme  # noqa: E402


COLS = 16
ADDR_WIDTH = 16
HEX_START = ADDR_WIDTH + 2  # after "FFFFFFFFFFFFFFFF  "
ASCII_START = HEX_START + COLS * 3 + 1
M64 = 0xFFFFFFFFFFFFFFFF
HEXDIGITS = "0123456789abcdefABCDEF"


def _ascii_char(b: int) -> str:
    return chr(b) if 32 <= b < 127 else "."


# ---------------------------------------------------------------- formatters
def fmt_hex(data: bytes, sep: str = " ") -> str:
    return sep.join(f"{b:02X}" for b in data)


def fmt_ascii(data: bytes) -> str:
    return "".join(_ascii_char(b) for b in data)


def fmt_escaped(data: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in data)


def fmt_c_array(data: bytes, name: str = "data") -> str:
    rows = [
        "    " + ", ".join(f"0x{b:02X}" for b in data[i : i + 12])
        for i in range(0, len(data), 12)
    ]
    return f"unsigned char {name}[{len(data)}] = {{\n" + ",\n".join(rows) + "\n};"


def fmt_dump(base: int, data: bytes) -> str:
    rows = []
    for off in range(0, len(data), COLS):
        chunk = data[off : off + COLS]
        rows.append(
            f"{(base + off) & M64:016X}  {fmt_hex(chunk):<{COLS * 3 - 1}}  {fmt_ascii(chunk)}"
        )
    return "\n".join(rows) + "\n"


COPY_KINDS = (
    # (key, menu label)
    ("hex", "Hex bytes   48 89 5C   (Ctrl+C)"),
    ("hex_compact", "Hex, no spaces   48895C"),
    ("escaped", "Escaped   \\x48\\x89\\x5c"),
    ("c_array", "C array"),
    ("ascii", "ASCII text"),
    ("dump", "Hex dump (address + hex + ascii)"),
    ("address", "Address of cursor   (Ctrl+Shift+C)"),
)


class HexEditor(ttk.Frame):
    def __init__(
        self,
        parent,
        on_cursor: Optional[Callable[[], None]] = None,
        on_message: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(parent)
        self.on_cursor = on_cursor
        self.on_message = on_message
        self.base = 0
        self.data = bytearray()
        self.orig = b""
        self.cursor = 0
        self.anchor: Optional[int] = None  # other end of the selection
        self.nibble = 0

        self.text = tk.Text(
            self,
            wrap="none",
            font=("Consolas", 11),
            undo=False,
            cursor="xterm",
            takefocus=True,
        )
        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        xscroll = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.text.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # creation order = priority: cursor draws over selection over dirty
        self.text.tag_configure("dirty", background=theme.c("hl_dirty"))
        self.text.tag_configure("selbyte", background=theme.c("hl_sel"))
        self.text.tag_configure("cursor", background=theme.c("cursor_bg"), foreground=theme.c("cursor_fg"))
        self.text.tag_configure("addr", foreground=theme.c("muted"))
        self.text.bind("<Button-1>", self._on_click)
        self.text.bind("<B1-Motion>", self._on_drag)
        self.text.bind("<Button-3>", self._on_right_click)
        self.text.bind("<Key>", self._on_key)
        self.text.bind("<Control-c>", lambda e: self.copy("hex"))
        self.text.bind("<Control-C>", lambda e: self.copy("address"))
        self.text.bind("<Control-a>", lambda e: self.select_all())
        self.text.bind("<Control-A>", lambda e: self.select_all())
        self.text.bind("<Tab>", lambda e: "break")
        self._ctx = self.build_menu(self.text)

    # ------------------------------------------------------------- data API
    def set_data(self, address: int, data: bytes) -> None:
        self.base = address & M64
        self.data = bytearray(data)
        self.orig = bytes(data)
        self.cursor = 0
        self.anchor = None
        self.nibble = 0
        self.render()

    def empty(self) -> bool:
        return not self.data

    def cursor_addr(self) -> int:
        return (self.base + self.cursor) & M64

    def dirty_count(self) -> int:
        return sum(1 for a, b in zip(self.data, self.orig) if a != b)

    def patches(self) -> list[tuple[int, bytes]]:
        runs: list[tuple[int, bytes]] = []
        start: Optional[int] = None
        for i, (cur, old) in enumerate(zip(self.data, self.orig)):
            if cur != old:
                if start is None:
                    start = i
            elif start is not None:
                runs.append((self.base + start, bytes(self.data[start:i])))
                start = None
        if start is not None:
            runs.append((self.base + start, bytes(self.data[start:])))
        return runs

    def revert(self) -> None:
        self.data = bytearray(self.orig)
        self.nibble = 0
        self.render()

    def value_at_cursor(self, size: int) -> Optional[int]:
        if self.cursor < 0 or self.cursor + size > len(self.data):
            return None
        return int.from_bytes(self.data[self.cursor : self.cursor + size], "little")

    # ------------------------------------------------------------ selection
    def selection_range(self) -> Optional[tuple[int, int]]:
        """(first, last) byte index, inclusive - or None if nothing is selected."""
        if not self.data or self.anchor is None or self.anchor == self.cursor:
            return None
        a = max(0, min(self.anchor, len(self.data) - 1))
        lo, hi = sorted((a, self.cursor))
        return lo, hi

    def current_bytes(self, whole_if_none: bool = False) -> tuple[int, bytes]:
        """(address, bytes) of the selection; else the cursor byte, or the whole
        view when `whole_if_none`."""
        if not self.data:
            return self.base, b""
        sel = self.selection_range()
        if sel:
            lo, hi = sel
            return (self.base + lo) & M64, bytes(self.data[lo : hi + 1])
        if whole_if_none:
            return self.base, bytes(self.data)
        return self.cursor_addr(), bytes(self.data[self.cursor : self.cursor + 1])

    def select_all(self) -> str:
        if self.data:
            self.anchor = 0
            self.cursor = len(self.data) - 1
            self.nibble = 0
            self._refresh_cursor()
        return "break"

    # ----------------------------------------------------------- copy / dump
    def _say(self, msg: str) -> None:
        if self.on_message:
            self.on_message(msg)

    def copy(self, kind: str = "hex") -> str:
        if not self.data:
            return "break"
        addr, data = self.current_bytes()
        if kind == "address":
            text, what = f"0x{self.cursor_addr():X}", "address"
        elif kind == "hex":
            text, what = fmt_hex(data), "hex"
        elif kind == "hex_compact":
            text, what = fmt_hex(data, ""), "hex (no spaces)"
        elif kind == "escaped":
            text, what = fmt_escaped(data), "escaped bytes"
        elif kind == "c_array":
            text, what = fmt_c_array(data), "C array"
        elif kind == "ascii":
            text, what = fmt_ascii(data), "ASCII"
        elif kind == "dump":
            text, what = fmt_dump(addr, data), "hex dump"
        else:
            return "break"
        self.clipboard_clear()
        self.clipboard_append(text)
        if kind == "address":
            self._say(f"copied address {text}")
        else:
            self._say(f"copied {len(data)} byte(s) from 0x{addr:X} as {what}")
        return "break"

    def save_file(self) -> None:
        """Save the selection (or the whole view) as raw .bin or text .txt dump."""
        addr, data = self.current_bytes(whole_if_none=True)
        if not data:
            messagebox.showerror("Hex editor", "Nothing loaded to save yet.")
            return
        path = filedialog.asksaveasfilename(
            title=f"Save {len(data)} byte(s) from 0x{addr:X}",
            defaultextension=".bin",
            initialfile=f"dump_{addr:X}.bin",
            filetypes=[("Raw binary", "*.bin"), ("Text hex dump", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            if path.lower().endswith(".txt"):
                Path(path).write_text(fmt_dump(addr, data), encoding="utf-8")
            else:
                Path(path).write_bytes(data)
        except OSError as exc:
            messagebox.showerror("Hex editor", f"Could not save: {exc}")
            return
        self._say(f"saved {len(data)} byte(s) from 0x{addr:X} to {path}")

    def build_menu(self, parent) -> tk.Menu:
        """A fresh Copy menu (used for right-click and for the toolbar button)."""
        m = tk.Menu(parent, tearoff=0)
        for key, label in COPY_KINDS:
            m.add_command(label=label, command=lambda k=key: self.copy(k))
        m.add_separator()
        m.add_command(label="Select all   (Ctrl+A)", command=self.select_all)
        m.add_separator()
        m.add_command(label="Save selection / view to file...", command=self.save_file)
        return m

    # --------------------------------------------------------------- render
    def render(self) -> None:
        self.text.configure(state="normal")
        yview = self.text.yview()
        self.text.delete("1.0", "end")
        if not self.data:
            self.text.insert("end", "Enter an address and click Go.\n")
            self.text.configure(state="disabled")
            return

        lines = (len(self.data) + COLS - 1) // COLS
        dirty = {i for i, (a, b) in enumerate(zip(self.data, self.orig)) if a != b}
        chunks: list[str] = []
        for row in range(lines):
            off = row * COLS
            chunk = self.data[off : off + COLS]
            addr = (self.base + off) & M64
            hexpart = " ".join(f"{b:02X}" for b in chunk)
            if len(chunk) < COLS:
                hexpart = hexpart + "   " * (COLS - len(chunk))
            ascii_part = "".join(_ascii_char(b) for b in chunk)
            chunks.append(f"{addr:016X}  {hexpart}  {ascii_part}")
        self.text.insert("1.0", "\n".join(chunks) + "\n")

        for idx in dirty:
            row, col = divmod(idx, COLS)
            line = row + 1
            h0 = HEX_START + col * 3
            self.text.tag_add("dirty", f"{line}.{h0}", f"{line}.{h0 + 2}")
            a0 = ASCII_START + col
            self.text.tag_add("dirty", f"{line}.{a0}", f"{line}.{a0 + 1}")

        for row in range(lines):
            self.text.tag_add("addr", f"{row + 1}.0", f"{row + 1}.{ADDR_WIDTH}")

        self._paint_cursor()
        self.text.yview_moveto(yview[0])
        self.text.configure(state="disabled")
        self.text.focus_set()
        if self.on_cursor:
            self.on_cursor()

    def _paint_selection(self) -> None:
        sel = self.selection_range()
        if not sel:
            return
        lo, hi = sel
        first_row, last_row = lo // COLS, hi // COLS
        for row in range(first_row, last_row + 1):
            c0 = lo % COLS if row == first_row else 0
            c1 = hi % COLS if row == last_row else COLS - 1
            line = row + 1
            self.text.tag_add("selbyte", f"{line}.{HEX_START + c0 * 3}", f"{line}.{HEX_START + c1 * 3 + 2}")
            self.text.tag_add("selbyte", f"{line}.{ASCII_START + c0}", f"{line}.{ASCII_START + c1 + 1}")

    def _paint_cursor(self) -> None:
        self.text.tag_remove("cursor", "1.0", "end")
        self.text.tag_remove("selbyte", "1.0", "end")
        if not self.data:
            return
        self.cursor = max(0, min(self.cursor, len(self.data) - 1))
        self._paint_selection()
        row, col = divmod(self.cursor, COLS)
        line = row + 1
        h0 = HEX_START + col * 3
        extra = 1 if self.nibble else 0
        self.text.tag_add("cursor", f"{line}.{h0 + extra}", f"{line}.{h0 + extra + 1}")
        a0 = ASCII_START + col
        self.text.tag_add("cursor", f"{line}.{a0}", f"{line}.{a0 + 1}")
        self.text.see(f"{line}.0")

    def _refresh_cursor(self) -> None:
        self.text.configure(state="normal")
        self._paint_cursor()
        self.text.configure(state="disabled")
        if self.on_cursor:
            self.on_cursor()

    # ---------------------------------------------------------------- mouse
    def _hit(self, event, strict: bool) -> Optional[tuple[int, int]]:
        """(byte index, nibble) under the mouse. strict: only real hex/ascii cells
        (clicks); otherwise clamp to the nearest byte (dragging)."""
        index = self.text.index(f"@{event.x},{event.y}")
        line_s, col_s = index.split(".")
        lines = (len(self.data) + COLS - 1) // COLS
        row = int(line_s) - 1
        col = int(col_s)
        if strict and not (0 <= row < lines):
            return None
        row = max(0, min(row, lines - 1))
        nibble = 0
        if HEX_START <= col < HEX_START + COLS * 3:
            byte_in_row = (col - HEX_START) // 3
            nibble = 1 if ((col - HEX_START) % 3) == 1 else 0
        elif ASCII_START <= col < ASCII_START + COLS:
            byte_in_row = col - ASCII_START
        elif strict:
            return None
        elif col < HEX_START:
            byte_in_row = 0
        elif col < ASCII_START:
            byte_in_row = COLS - 1
        else:
            byte_in_row = COLS - 1
        idx = min(row * COLS + byte_in_row, len(self.data) - 1)
        if strict and row * COLS + byte_in_row >= len(self.data):
            return None
        return idx, nibble

    def _on_click(self, event) -> str:
        self.text.focus_set()
        if not self.data:
            return "break"
        hit = self._hit(event, strict=True)
        if hit is None:
            return "break"
        idx, nibble = hit
        if (event.state & 0x1) and self.anchor is None:
            self.anchor = self.cursor  # shift+click extends from the old cursor
        elif not (event.state & 0x1):
            self.anchor = idx
        self.cursor = idx
        self.nibble = nibble
        self._refresh_cursor()
        return "break"

    def _on_drag(self, event) -> str:
        if not self.data:
            return "break"
        height = self.text.winfo_height()
        if event.y < 0:
            self.text.yview_scroll(-1, "units")
        elif event.y > height:
            self.text.yview_scroll(1, "units")
        hit = self._hit(event, strict=False)
        if hit is not None:
            if self.anchor is None:
                self.anchor = self.cursor
            self.cursor = hit[0]
            self.nibble = 0
            self._refresh_cursor()
        return "break"

    def _on_right_click(self, event) -> str:
        self.text.focus_set()
        if self.data:
            hit = self._hit(event, strict=True)
            sel = self.selection_range()
            if hit is not None and not (sel and sel[0] <= hit[0] <= sel[1]):
                self.cursor, self.anchor, self.nibble = hit[0], hit[0], 0
                self._refresh_cursor()
        try:
            self._ctx.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx.grab_release()
        return "break"

    # ------------------------------------------------------------- keyboard
    def _on_key(self, event) -> str:
        if not self.data:
            return "break"
        key = event.keysym
        shift = bool(event.state & 0x1)
        n = len(self.data)
        if key in ("Left", "Right", "Up", "Down", "Home", "End"):
            if shift and self.anchor is None:
                self.anchor = self.cursor
            c = self.cursor
            if key == "Left":
                c = max(0, c - 1)
            elif key == "Right":
                c = min(n - 1, c + 1)
            elif key == "Up":
                c = max(0, c - COLS)
            elif key == "Down":
                c = min(n - 1, c + COLS)
            elif key == "Home":
                c = c - (c % COLS)
            else:  # End
                c = min(n - 1, c - (c % COLS) + COLS - 1)
            self.cursor = c
            self.nibble = 0
            if not shift:
                self.anchor = c
        elif key in ("Prior", "Next"):
            return ""  # let the parent handle paging if bound
        elif event.char and event.char in HEXDIGITS:
            nibble_val = int(event.char, 16)
            cur = self.data[self.cursor]
            if self.nibble == 0:
                self.data[self.cursor] = (nibble_val << 4) | (cur & 0x0F)
                self.nibble = 1
                self.anchor = self.cursor
                self.render()
                return "break"
            self.data[self.cursor] = (cur & 0xF0) | nibble_val
            self.nibble = 0
            if self.cursor + 1 < n:
                self.cursor += 1
            self.anchor = self.cursor
            self.render()
            return "break"
        else:
            return "break"

        self._refresh_cursor()
        return "break"
