"""Compact cheat packs: export / import cheats (+ the item lists they use).

File  (*.ps5c):  b"PS5C1\\n" + zlib(minified JSON)
Code  (text):    "PS5C1:" + base64url(zlib(minified JSON))   - paste in chat / forum

JSON: {"format": "ps5pack/1", "games": [<game file dict>...], "items": {list: {name: id}}}
"""

from __future__ import annotations

import base64
import json
import re
import zlib
from pathlib import Path
from typing import Iterable, Optional

from cheats import Cheat, Game

MAGIC = b"PS5C1\n"
CODE_PREFIX = "PS5C1:"


def build_pack(games: Iterable[tuple[Game, list[Cheat]]], items_store=None) -> dict:
    out_games, lists = [], {}
    for game, cheats in games:
        d = game.to_dict()
        d["cheats"] = [c.to_dict() for c in cheats]
        out_games.append(d)
        for c in cheats:
            for p in c.params:
                lst = p.get("items")
                if lst and items_store is not None and items_store.items(lst):
                    lists[lst] = items_store.items(lst)
    return {"format": "ps5pack/1", "games": out_games, "items": lists}


def _blob(pack: dict) -> bytes:
    return zlib.compress(json.dumps(pack, separators=(",", ":"), ensure_ascii=False).encode("utf-8"), 9)


def to_file_bytes(pack: dict) -> bytes:
    return MAGIC + _blob(pack)


def to_code(pack: dict) -> str:
    return CODE_PREFIX + base64.urlsafe_b64encode(_blob(pack)).decode("ascii").rstrip("=")


def parse(data: bytes | str) -> dict:
    """Accepts a .ps5c file, a share code, a pack JSON or a plain game JSON file."""
    if isinstance(data, bytes):
        if data.startswith(MAGIC):
            return _check(json.loads(zlib.decompress(data[len(MAGIC):]).decode("utf-8")))
        data = data.decode("utf-8-sig")
    text = data.strip()
    if text.startswith(CODE_PREFIX):
        raw = re.sub(r"\s+", "", text[len(CODE_PREFIX):])
        raw += "=" * (-len(raw) % 4)
        return _check(json.loads(zlib.decompress(base64.urlsafe_b64decode(raw)).decode("utf-8")))
    d = json.loads(text)
    if isinstance(d, dict) and d.get("format") == "ps5pack/1":
        return _check(d)
    if isinstance(d, dict) and d.get("game"):
        return {"format": "ps5pack/1", "games": [d], "items": {}}
    raise ValueError("not a cheat pack, share code or cheat file")


def _check(pack: dict) -> dict:
    if not isinstance(pack.get("games"), list):
        raise ValueError("broken cheat pack (no games)")
    for g in pack["games"]:
        Game.from_dict(g)       # validates every cheat
    return pack


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "game"


def merge_into(pack: dict, games: list[Game], folder: Path, items_store=None,
               source: Optional[str] = None) -> list[str]:
    """Add the pack's cheats to game files, creating new files when needed.  Same name + same
    content is skipped; same name + different content is added as 'name (imported)'.

    source = the imported file's name: its cheats go into their own game entry
    ("Game (file.mc4)", file <file>_<ext>.json), so cheats from different files / formats of
    the same game never mix; importing the same file again updates that entry.
    No source (share code): merged into the game with the same title id, else the same name.
    Returns a log of what happened."""
    log: list[str] = []
    folder.mkdir(parents=True, exist_ok=True)
    # item lists first: new ones are written, existing ones get missing entries added
    for lst, entries in (pack.get("items") or {}).items():
        if items_store is None or not isinstance(entries, dict):
            continue
        idir = folder / "items"
        idir.mkdir(parents=True, exist_ok=True)
        path = idir / f"{_slug(lst)}.json"
        cur = dict(items_store.items(lst))
        if not cur and path.exists():
            try:
                cur = {k: int(v, 0) if isinstance(v, str) else int(v)
                       for k, v in json.loads(path.read_text(encoding="utf-8")).items()}
            except Exception:
                cur = {}
        added = {k: v for k, v in entries.items() if k not in cur}
        if not cur or added:
            cur.update(added)
            path.write_text(json.dumps(cur, indent=2, ensure_ascii=False), encoding="utf-8")
            log.append(f"item list '{lst}': {len(added)} item(s) added")
    import game_ids  # noqa: PLC0415
    for gd in pack["games"]:
        src = Game.from_dict(gd)            # older files are corrected to the naming standard here
        if src.fixed:
            log.append(f"{src.name}: " + "; ".join(src.fixed))
        tid = src.title_id.upper()
        many = len(pack["games"]) > 1
        tag = f"{source}" + (f" #{tid or src.name}" if many else "") if source else ""

        def same_version(g: Game) -> bool:     # cheats for another app version never mix (offsets differ)
            return not src.version or not g.version or g.version == src.version
        if tag:
            dst = next((g for g in games if g.source == tag), None)
        else:
            dst = next((g for g in games if tid and g.title_id.upper() == tid and not g.source
                        and g.version == src.version), None) or \
                next((g for g in games if tid and g.title_id.upper() == tid and not g.source and same_version(g)), None) or \
                next((g for g in games if not tid and g.name == src.name and not g.source), None)
        if dst is None:
            ext = Path(source).suffix.lstrip(".") if source else ""
            if ext.lower() in ("ps5c", "json"):
                ext = ""                       # this tool's own files: just <TITLEID>_<VERSION>.json
            if tid:
                path = game_ids.library_path(folder, tid, src.version, src.name, suffix=ext)
            else:
                stem = _slug(Path(source).stem + "_" + ext if source else src.name)
                path = game_ids.library_path(folder, "", "", stem)
            name = f"{src.name} ({source})" if source else src.name
            dst = Game(name, src.title_id, src.version, src.process, src.author, src.notes, [], path, tag,
                       content_id=src.content_id)
            games.append(dst)
            log.append(f"new game file {path.name}")
        else:                                  # fill what the existing entry does not know yet
            dst.version = dst.version or src.version
            dst.content_id = dst.content_id or src.content_id
            dst.process = dst.process or src.process
        added = skipped = 0
        for c in src.cheats:
            same = next((x for x in dst.cheats if x.name == c.name), None)
            if same is not None and same.to_dict() == c.to_dict():
                skipped += 1
                continue
            if same is not None:
                base, k = f"{c.name} (imported)", 2
                c.name = base
                while any(x.name == c.name for x in dst.cheats):
                    c.name = f"{base} {k}"
                    k += 1
            dst.cheats.append(c)
            added += 1
        dst.save()
        log.append(f"{dst.name}: {added} cheat(s) added" + (f", {skipped} already there" if skipped else ""))
    return log
