"""Cheat projects: one folder that holds everything you make for your games.

    <project>/                  game cheat files  (<TITLEID>.json, ps5cheat/1)
    <project>/items/            item ID lists     ({"item name": id} .json - used by cheat inputs)
    <project>/exports/          exported .shn / .mc4 / GoldHEN .json / .ps5c files
    <project>/deleted/          deleted game files (can be restored by moving them back)
    <project>/project.ps5proj   name, author, created date, notes

The tool's own `cheats` folder is the default project.
"""

from __future__ import annotations

import datetime
import json
import re
from pathlib import Path

from app_paths import APP_DIR

DEFAULT_DIR = APP_DIR / "cheats"
META = "project.ps5proj"
SUBDIRS = ("items", "exports")


def slug(text: str) -> str:
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", text).strip(" ._") or "project"


def info(path: Path) -> dict:
    p = Path(path)
    d = {"name": p.name if p != DEFAULT_DIR else "Default (cheats folder)", "author": "", "notes": "", "created": ""}
    try:
        d.update(json.loads((p / META).read_text(encoding="utf-8")))
    except Exception:
        pass
    return d


def ensure(path: Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    for s in SUBDIRS:
        (p / s).mkdir(exist_ok=True)
    return p


def create(parent: Path, name: str, author: str = "", notes: str = "") -> Path:
    """New project folder <parent>/<name>.  Raises FileExistsError if it already has files."""
    p = Path(parent) / slug(name)
    if p.exists() and any(p.iterdir()):
        raise FileExistsError(f"{p} already exists and is not empty")
    ensure(p)
    (p / META).write_text(json.dumps({"name": name, "author": author, "notes": notes,
                                      "created": datetime.date.today().isoformat()}, indent=2), encoding="utf-8")
    return p


def counts(path: Path) -> tuple[int, int]:
    """(game files, item lists)"""
    p = Path(path)
    return len(list(p.glob("*.json"))), len(list((p / "items").glob("*.json")))
