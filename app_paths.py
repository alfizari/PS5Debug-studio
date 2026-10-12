"""Where the tool keeps its files (settings, cheats, tables, scripts, pointer scans).

Running from source: the folder of the .py files.  Running as the compiled .exe: the folder the
.exe is in (PyInstaller unpacks the code to a temporary folder that is deleted on exit, so data
must never be written next to __file__ there)."""

from __future__ import annotations

import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent

# Read-only files shipped with the tool (icon ...): inside the exe they are unpacked to sys._MEIPASS.
RES_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
ASSETS = RES_DIR / "assets"


def set_window_icon(root) -> None:
    """Tool icon on the window, its dialogs and the taskbar (no error if the files are missing)."""
    try:
        if sys.platform == "win32" and (ASSETS / "icon.ico").exists():
            root.iconbitmap(default=str(ASSETS / "icon.ico"))   # default= also covers every Toplevel
            return
        if (ASSETS / "icon.png").exists():
            import tkinter as tk
            img = tk.PhotoImage(file=str(ASSETS / "icon.png"))
            root.iconphoto(True, img)
            root._tool_icon = img                                # keep a reference
    except Exception:
        pass
