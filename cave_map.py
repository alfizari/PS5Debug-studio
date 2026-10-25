"""A record of where code caves were placed in a game's executable, per game + version.

When you export code-cave cheats to .shn / .mc4 / GoldHEN .json, the cave code goes into free space
inside the game executable (see cheat_export._static_caves).  If a later export reused the same
offset, the two caves would overlap.  This keeps a small on-disk record of the regions already used,
so "Find free space" skips them and a new export lands somewhere else.

Stored as <project>/cavemap.json:
    { "CUSA12345_01.00": [ {"off": 1826816, "len": 48, "label": "Inf HP (file.shn)"}, ... ], ... }
offsets/lengths are plain ints (module(main)+off).  Reserved regions are kept sorted and merged.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

FILE = "cavemap.json"


def _key(title_id: str, version: str) -> str:
    t = (title_id or "").strip().upper()
    v = (version or "").strip()
    return f"{t}_{v}" if v else (t or "game")


def _path(folder) -> Path:
    return Path(folder) / FILE


def load(folder) -> dict:
    try:
        d = json.loads(_path(folder).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save(folder, data: dict) -> None:
    try:
        _path(folder).write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def regions(folder, title_id: str, version: str) -> list:
    """[(off, length, label)] reserved for this game+version, sorted by offset."""
    out = []
    for r in load(folder).get(_key(title_id, version), []):
        try:
            out.append((int(r["off"]), int(r["len"]), str(r.get("label", ""))))
        except Exception:
            continue
    return sorted(out)


def reserve(folder, title_id: str, version: str, off: int, length: int, label: str = "") -> None:
    """Record [off, off+length) as used.  Overlapping / identical entries with the same label merge."""
    if length <= 0:
        return
    data = load(folder)
    key = _key(title_id, version)
    rows = data.get(key, [])
    rows.append({"off": int(off), "len": int(length), "label": str(label)})
    # merge entries that touch/overlap and share a label, so the record stays tidy
    rows.sort(key=lambda r: (int(r["off"]), str(r.get("label", ""))))
    merged: list = []
    for r in rows:
        o, n, lbl = int(r["off"]), int(r["len"]), str(r.get("label", ""))
        if merged and lbl == merged[-1]["label"] and o <= merged[-1]["off"] + merged[-1]["len"]:
            end = max(merged[-1]["off"] + merged[-1]["len"], o + n)
            merged[-1]["len"] = end - merged[-1]["off"]
        else:
            merged.append({"off": o, "len": n, "label": lbl})
    data[key] = merged
    save(folder, data)


def remove(folder, title_id: str, version: str, off: int) -> None:
    data = load(folder)
    key = _key(title_id, version)
    rows = [r for r in data.get(key, []) if int(r.get("off", -1)) != int(off)]
    if rows:
        data[key] = rows
    else:
        data.pop(key, None)
    save(folder, data)


def clear(folder, title_id: str, version: str) -> None:
    data = load(folder)
    data.pop(_key(title_id, version), None)
    save(folder, data)


def is_free(reserved: list, off: int, length: int) -> bool:
    """Does [off, off+length) avoid every reserved region?  `reserved` = list of (off, len, label)."""
    for ro, rn, _lbl in reserved:
        if off < ro + rn and ro < off + length:
            return False
    return True


def subtract(run_start: int, run_len: int, reserved: list):
    """Yield (start, length) sub-runs of [run_start, run_start+run_len) with reserved regions removed."""
    cuts = sorted((ro, rn) for ro, rn, _l in reserved if ro < run_start + run_len and ro + rn > run_start)
    pos = run_start
    end = run_start + run_len
    for ro, rn in cuts:
        if ro > pos:
            yield (pos, ro - pos)
        pos = max(pos, ro + rn)
        if pos >= end:
            return
    if pos < end:
        yield (pos, end - pos)
