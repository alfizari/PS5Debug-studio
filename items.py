"""Item lists ({"item name": item_id} JSON files) + a type-to-filter combobox."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from tkinter import ttk
from typing import Callable, Optional


def parse_items(data) -> dict[str, int]:
    if not isinstance(data, dict):
        raise ValueError('items file must be a JSON object: {"item name": item_id}')
    out: dict[str, int] = {}
    for k, v in data.items():
        try:
            out[str(k)] = int(v, 0) if isinstance(v, str) else int(v)
        except (TypeError, ValueError):
            raise ValueError(f"bad id for '{k}': {v!r}") from None
    return out


class ItemStore:
    """All *.json files in <folder> become item lists, named after the file."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.lists: dict[str, dict[str, int]] = {}
        self.on_change: list[Callable[[], None]] = []

    def reload(self) -> list[str]:
        self.lists.clear()
        errors: list[str] = []
        self.folder.mkdir(parents=True, exist_ok=True)
        for p in sorted(self.folder.glob("*.json")):
            try:
                self.lists[p.stem] = parse_items(json.loads(p.read_text(encoding="utf-8")))
            except Exception as exc:
                errors.append(f"{p.name}: {exc}")
        return errors

    def import_file(self, src: Path) -> str:
        parse_items(json.loads(Path(src).read_text(encoding="utf-8")))  # validate first
        self.folder.mkdir(parents=True, exist_ok=True)
        dst = self.folder / Path(src).name
        if Path(src).resolve() != dst.resolve():
            shutil.copy(src, dst)
        self.reload()
        for cb in self.on_change:
            cb()
        return dst.stem

    def names(self) -> list[str]:
        return sorted(self.lists)

    def items(self, list_name: str) -> dict[str, int]:
        return self.lists.get(list_name, {})

    def lookup(self, list_name: str, text: str) -> Optional[int]:
        d = self.lists.get(list_name)
        if not d:
            return None
        if text in d:
            return d[text]
        low = text.strip().lower()
        for k, v in d.items():
            if k.lower() == low:
                return v
        return None

    def name_of(self, list_name: str, value: int) -> Optional[str]:
        for k, v in self.lists.get(list_name, {}).items():
            if v == value:
                return k
        return None


class SearchCombobox(ttk.Combobox):
    """Combobox whose dropdown narrows as you type (open the arrow to see matches)."""

    SKIP = {"Up", "Down", "Left", "Right", "Return", "Tab", "Escape",
            "Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R"}

    def __init__(self, parent, **kw) -> None:
        super().__init__(parent, **kw)
        self._all: list[str] = []
        self.bind("<KeyRelease>", self._filter, add="+")

    def set_values(self, values) -> None:
        self._all = list(values)
        self.configure(values=self._all[:500])

    def _filter(self, event) -> None:
        if event.keysym in self.SKIP:
            return
        t = self.get().strip().lower()
        vals = [v for v in self._all if t in v.lower()] if t else self._all
        self.configure(values=vals[:500])
