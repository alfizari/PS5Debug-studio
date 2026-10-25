"""Light / dark look for the whole app (ttk 'clam' base, restyled).

theme.apply(root, "light"|"dark") must run before the widgets are built;
everything that needs a colour asks theme.c("key") so both palettes work.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

PALETTES: dict[str, dict[str, str]] = {
    "light": {
        "bg": "#f3f4f6", "surface": "#ffffff", "surface2": "#f8fafc", "fg": "#1f2328",
        "muted": "#6b7280", "border": "#d5d9e0", "accent": "#2563eb", "accent_fg": "#ffffff",
        "accent_hover": "#1d4ed8", "select": "#dbe7ff", "select_fg": "#111827",
        "danger": "#c62828", "ok": "#15803d", "warn": "#b45309",
        "call": "#1a5fb4", "jmp": "#7a3e9d", "jcc": "#8a5a00",
        "hl_rip": "#fff2a8", "hl_bp": "#ffd9d9", "hl_ripbp": "#ffbf80",
        "hl_dirty": "#fff3b0", "hl_sel": "#bcd7ff", "cursor_bg": "#2b6cb0", "cursor_fg": "#ffffff",
        "changed": "#d32f2f", "frozen": "#0b6bcb", "stripe": "#f6f8fb", "btn": "#ffffff", "btn_hover": "#eef2f7",
        "entry": "#ffffff", "heading": "#eef1f5", "tab": "#e7eaf0", "trough": "#e5e7eb",
    },
    "dark": {
        "bg": "#1e1f22", "surface": "#26282c", "surface2": "#2b2d31", "fg": "#e3e5e8",
        "muted": "#9aa0a8", "border": "#3a3d43", "accent": "#4c8dff", "accent_fg": "#0b1220",
        "accent_hover": "#6aa1ff", "select": "#2e4a78", "select_fg": "#ffffff",
        "danger": "#ff6b6b", "ok": "#4ade80", "warn": "#fbbf24",
        "call": "#7cb3ff", "jmp": "#c79bf2", "jcc": "#e0b34f",
        "hl_rip": "#5a4d12", "hl_bp": "#5a2626", "hl_ripbp": "#6b4316",
        "hl_dirty": "#5b5214", "hl_sel": "#2f4f86", "cursor_bg": "#4c8dff", "cursor_fg": "#0b1220",
        "changed": "#ff7a7a", "frozen": "#7cb3ff", "stripe": "#2a2c30", "btn": "#2f3237", "btn_hover": "#383b41",
        "entry": "#2b2d31", "heading": "#2f3237", "tab": "#2a2c30", "trough": "#2b2d31",
    },
}

_current = "light"
UI_FONT = ("Segoe UI", 10)
MONO_FONT = ("Consolas", 10)


def c(key: str) -> str:
    return PALETTES[_current].get(key, "#ff00ff")


def name() -> str:
    return _current


def mono(size: int = 10, *style: str) -> tuple:
    return (MONO_FONT[0], size, *style)


def _install_edit_menu(root: tk.Tk) -> None:
    """A right-click Cut / Copy / Paste / Select all menu on every entry, combobox and text box
    (addresses, values, the cheat JSON...).  Installed once per class, app-wide."""
    if getattr(root, "_edit_menu_installed", False):
        return
    root._edit_menu_installed = True

    def popup(event):
        w = event.widget
        try:
            editable = str(w.cget("state")) not in ("disabled", "readonly")
        except tk.TclError:
            editable = True
        is_text = w.winfo_class() == "Text"
        try:
            w.focus_set()
        except tk.TclError:
            return
        m = tk.Menu(w, tearoff=0)
        def ev(seq):
            return lambda: w.event_generate(seq)
        if editable:
            m.add_command(label="Cut", command=ev("<<Cut>>"))
        m.add_command(label="Copy", command=ev("<<Copy>>"))
        if editable:
            m.add_command(label="Paste", command=ev("<<Paste>>"))
        m.add_separator()
        if is_text:
            m.add_command(label="Select all",
                          command=lambda: (w.tag_add("sel", "1.0", "end"), w.mark_set("insert", "1.0")))
        else:
            m.add_command(label="Select all", command=ev("<<SelectAll>>"))
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()
        return "break"

    for cls in ("TEntry", "Entry", "TCombobox", "Text", "TSpinbox", "Spinbox"):
        root.bind_class(cls, "<Button-3>", popup, add="+")
        root.bind_class(cls, "<Button-2>", popup, add="+")      # mac


def apply(root: tk.Tk, which: str = "light") -> None:
    global _current, UI_FONT, MONO_FONT
    _install_edit_menu(root)
    _current = which if which in PALETTES else "light"
    p = PALETTES[_current]

    families = set(tkfont.families(root))
    ui = next((f for f in ("Segoe UI", "SF Pro Text", "Inter", "Noto Sans", "DejaVu Sans") if f in families),
              "TkDefaultFont")
    mo = next((f for f in ("Cascadia Mono", "Consolas", "JetBrains Mono", "Menlo", "DejaVu Sans Mono")
               if f in families), "TkFixedFont")
    UI_FONT, MONO_FONT = (ui, 10), (mo, 10)
    for fname in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(fname).configure(family=ui, size=10)
        except tk.TclError:
            pass
    try:
        tkfont.nametofont("TkFixedFont").configure(family=mo, size=10)
    except tk.TclError:
        pass

    root.configure(background=p["bg"])
    # classic tk widgets created later pick these up
    for opt, val in (
        ("*Text.background", p["surface"]), ("*Text.foreground", p["fg"]),
        ("*Text.insertBackground", p["fg"]), ("*Text.selectBackground", p["select"]),
        ("*Text.selectForeground", p["select_fg"]), ("*Text.relief", "flat"),
        ("*Text.highlightThickness", 1), ("*Text.highlightBackground", p["border"]),
        ("*Text.highlightColor", p["accent"]),
        ("*Canvas.background", p["bg"]), ("*Canvas.highlightThickness", 0),
        ("*Listbox.background", p["surface"]), ("*Listbox.foreground", p["fg"]),
        ("*Listbox.selectBackground", p["select"]), ("*Listbox.selectForeground", p["select_fg"]),
        ("*Menu.background", p["surface"]), ("*Menu.foreground", p["fg"]),
        ("*Menu.activeBackground", p["select"]), ("*Menu.activeForeground", p["select_fg"]),
        ("*Menu.relief", "flat"), ("*Toplevel.background", p["bg"]),
        ("*TCombobox*Listbox.background", p["surface"]), ("*TCombobox*Listbox.foreground", p["fg"]),
        ("*TCombobox*Listbox.selectBackground", p["select"]),
        ("*TCombobox*Listbox.selectForeground", p["select_fg"]),
    ):
        root.option_add(opt, val)

    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=p["bg"], foreground=p["fg"], fieldbackground=p["entry"],
                bordercolor=p["border"], lightcolor=p["bg"], darkcolor=p["bg"], troughcolor=p["trough"],
                selectbackground=p["select"], selectforeground=p["select_fg"], insertcolor=p["fg"],
                font=UI_FONT, focuscolor=p["accent"])
    s.map(".", foreground=[("disabled", p["muted"])])
    s.configure("TFrame", background=p["bg"])
    s.configure("Card.TFrame", background=p["surface"])
    s.configure("TLabel", background=p["bg"], foreground=p["fg"])
    s.configure("Muted.TLabel", foreground=p["muted"])
    s.configure("Title.TLabel", font=(ui, 11, "bold"))
    s.configure("Big.TLabel", font=(ui, 13, "bold"))
    s.configure("Status.TLabel", background=p["surface2"], foreground=p["muted"], padding=(8, 3))
    s.configure("Good.TLabel", foreground=p["ok"])
    s.configure("Bad.TLabel", foreground=p["danger"])
    s.configure("TLabelframe", background=p["bg"], bordercolor=p["border"], relief="solid", borderwidth=1)
    s.configure("TLabelframe.Label", background=p["bg"], foreground=p["muted"], font=(ui, 9, "bold"))

    s.configure("TButton", background=p["btn"], foreground=p["fg"], bordercolor=p["border"],
                lightcolor=p["btn"], darkcolor=p["btn"], padding=(10, 4), relief="flat", width=-6)
    s.map("TButton",
          background=[("disabled", p["surface2"]), ("pressed", p["select"]), ("active", p["btn_hover"])],
          lightcolor=[("active", p["btn_hover"])], darkcolor=[("active", p["btn_hover"])],
          bordercolor=[("focus", p["accent"])])
    s.configure("Accent.TButton", background=p["accent"], foreground=p["accent_fg"],
                lightcolor=p["accent"], darkcolor=p["accent"], bordercolor=p["accent"],
                font=(ui, 10, "bold"))
    s.map("Accent.TButton",
          background=[("disabled", p["border"]), ("pressed", p["accent_hover"]), ("active", p["accent_hover"])],
          lightcolor=[("active", p["accent_hover"])], darkcolor=[("active", p["accent_hover"])],
          foreground=[("disabled", p["muted"])])
    s.configure("Danger.TButton", foreground=p["danger"])
    s.configure("Small.TButton", padding=(6, 2))
    s.configure("Tool.TButton", padding=(6, 2), relief="flat", background=p["bg"], bordercolor=p["bg"],
                lightcolor=p["bg"], darkcolor=p["bg"])
    s.map("Tool.TButton", background=[("active", p["btn_hover"])], bordercolor=[("active", p["border"])])

    s.configure("TEntry", fieldbackground=p["entry"], foreground=p["fg"], bordercolor=p["border"],
                lightcolor=p["entry"], darkcolor=p["entry"], padding=(4, 3))
    s.map("TEntry", bordercolor=[("focus", p["accent"])], lightcolor=[("focus", p["accent"])],
          fieldbackground=[("readonly", p["surface2"]), ("disabled", p["bg"])])
    s.configure("TCombobox", fieldbackground=p["entry"], foreground=p["fg"], background=p["btn"],
                bordercolor=p["border"], lightcolor=p["entry"], darkcolor=p["entry"], arrowcolor=p["fg"],
                padding=(4, 2))
    s.map("TCombobox", fieldbackground=[("readonly", p["entry"])], bordercolor=[("focus", p["accent"])],
          selectbackground=[("readonly", p["entry"])], selectforeground=[("readonly", p["fg"])],
          background=[("active", p["btn_hover"])])
    s.configure("TSpinbox", fieldbackground=p["entry"], foreground=p["fg"], arrowcolor=p["fg"],
                bordercolor=p["border"], lightcolor=p["entry"], darkcolor=p["entry"])
    s.configure("TCheckbutton", background=p["bg"], foreground=p["fg"], indicatorbackground=p["entry"],
                indicatorforeground=p["accent"], upperbordercolor=p["border"], lowerbordercolor=p["border"])
    s.map("TCheckbutton", background=[("active", p["bg"])],
          indicatorbackground=[("selected", p["accent"]), ("active", p["btn_hover"])],
          indicatorforeground=[("selected", p["accent_fg"])])
    s.configure("TRadiobutton", background=p["bg"], foreground=p["fg"], indicatorbackground=p["entry"])
    s.map("TRadiobutton", background=[("active", p["bg"])],
          indicatorbackground=[("selected", p["accent"])])

    s.configure("TNotebook", background=p["bg"], bordercolor=p["border"], tabmargins=(6, 4, 6, 0))
    s.configure("TNotebook.Tab", background=p["tab"], foreground=p["muted"], padding=(14, 6),
                bordercolor=p["border"], lightcolor=p["tab"], darkcolor=p["tab"], font=(ui, 10))
    s.map("TNotebook.Tab",
          background=[("selected", p["surface"]), ("active", p["btn_hover"])],
          foreground=[("selected", p["fg"])],
          lightcolor=[("selected", p["surface"])], darkcolor=[("selected", p["surface"])],
          expand=[("selected", (0, 2, 0, 0))])

    s.configure("Treeview", background=p["surface"], fieldbackground=p["surface"], foreground=p["fg"],
                bordercolor=p["border"], lightcolor=p["surface"], darkcolor=p["surface"], rowheight=22)
    s.map("Treeview", background=[("selected", p["select"])], foreground=[("selected", p["select_fg"])])
    s.configure("Treeview.Heading", background=p["heading"], foreground=p["muted"], relief="flat",
                bordercolor=p["border"], lightcolor=p["heading"], darkcolor=p["heading"], font=(ui, 9, "bold"),
                padding=(6, 3))
    s.map("Treeview.Heading", background=[("active", p["btn_hover"])])

    s.configure("TScrollbar", background=p["btn"], troughcolor=p["bg"], bordercolor=p["bg"],
                lightcolor=p["btn"], darkcolor=p["btn"], arrowcolor=p["muted"], gripcount=0)
    s.map("TScrollbar", background=[("active", p["btn_hover"])])
    s.configure("TProgressbar", background=p["accent"], troughcolor=p["trough"], bordercolor=p["trough"],
                lightcolor=p["accent"], darkcolor=p["accent"], thickness=8)
    s.configure("TPanedwindow", background=p["bg"])
    s.configure("Sash", sashthickness=6, gripcount=0, background=p["bg"])
    s.configure("TSeparator", background=p["border"])
    s.configure("TMenubutton", background=p["btn"], foreground=p["fg"], bordercolor=p["border"],
                lightcolor=p["btn"], darkcolor=p["btn"], arrowcolor=p["fg"], padding=(8, 3))
    s.map("TMenubutton", background=[("active", p["btn_hover"])])



def stripe(tree: ttk.Treeview) -> None:
    """Zebra rows: call once after creating a Treeview, then tag rows 'odd'."""
    tree.tag_configure("odd", background=c("stripe"))
