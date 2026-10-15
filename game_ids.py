"""One naming standard for game entries - the same fields ShnExt / Reaper Studio and the GoldHEN
cheat menus use, read from the console the same way (title id + content id from the process,
app version from the title's param.sfo / param.json).

  title_id    CUSA##### (PS4) or PPSA##### (PS5), upper case
  content_id  e.g. UP0700-CUSA08155_00-DARKSOULS3BST000 (optional)
  version     the app version: 01.03 on PS4, 01.000.000 on PS5 (zero padded)
  process     eboot.bin unless the game runs another executable
  file name   <TITLEID>_<VERSION>.json, or <TITLEID>.json while the version is unknown
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TITLE_RE = re.compile(r"(?<![A-Za-z0-9])((?:CUSA|PPSA)\d{5})(?!\d)", re.IGNORECASE)
CONTENT_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2}\d{4}-(?:CUSA|PPSA)\d{5}_\d{2}-[A-Z0-9]{16})(?![A-Za-z0-9])",
                        re.IGNORECASE)
TITLE_ID_FULL = re.compile(r"(?:CUSA|PPSA)\d{5}")
PS4_VERSION = re.compile(r"\d{2}\.\d{2}")
PS5_VERSION = re.compile(r"\d{2}\.\d{3}\.\d{3}")


def title_id(*texts: str) -> str:
    """The first CUSA#####/PPSA##### found in the texts (title id, content id, name, file name)."""
    for t in texts:
        m = TITLE_RE.search(str(t or "").replace("_", " "))   # "_" counts as a separator here
        if m:
            return m.group(1).upper()
    return ""


def content_id(*texts: str) -> str:
    for t in texts:
        m = CONTENT_RE.search(str(t or ""))
        if m:
            return m.group(1).upper()
    return ""


def version(text: str, tid: str = "") -> str:
    """App version in the console's own spelling.  PS4: 1.3 / v01.03 / 01.03.000 -> 01.03;
    PS5: 1.0 / 01.000.000 -> 01.000.000.  Text that is not a version is returned unchanged."""
    raw = str(text or "").strip()
    v = re.sub(r"(?i)^(?:v(?:er(?:sion)?)?\.?\s*)", "", raw).strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){0,2}", v):
        return raw
    parts = [int(x) for x in v.split(".")]
    ps5 = tid.upper().startswith("PPSA") if tid else len(parts) == 3
    if ps5:
        parts = (parts + [0, 0, 0])[:3]
        if parts[0] > 99 or parts[1] > 999 or parts[2] > 999:
            return raw
        return f"{parts[0]:02d}.{parts[1]:03d}.{parts[2]:03d}"
    if len(parts) == 3 and parts[2] != 0:
        return raw                                    # 01.03.002 on PS4 is not something to guess at
    parts = (parts + [0, 0])[:2]
    if parts[0] > 99 or parts[1] > 99:
        return raw
    return f"{parts[0]:02d}.{parts[1]:02d}"


def version_ok(ver: str, tid: str = "") -> bool:
    if tid.upper().startswith("PPSA"):
        return bool(PS5_VERSION.fullmatch(ver or ""))
    if tid.upper().startswith("CUSA"):
        return bool(PS4_VERSION.fullmatch(ver or ""))
    return bool(PS4_VERSION.fullmatch(ver or "") or PS5_VERSION.fullmatch(ver or ""))


def file_stem(tid: str, ver: str, fallback: str = "game") -> str:
    """<TITLEID>_<VERSION> - the name cheat menus look for (GoldHEN, ShnExt, etaHEN)."""
    tid = (tid or "").strip().upper()
    if not tid:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", fallback).strip("_") or "game"
    return f"{tid}_{ver}" if ver and version_ok(ver, tid) else tid


def normalize(meta: dict, file_name: str = "") -> tuple[dict, list[str]]:
    """Game metadata (game / title_id / content_id / version / process) -> the standard spelling.
    Returns (new dict, what changed).  Only fixes what is certain; never invents a version."""
    d = dict(meta)
    changes: list[str] = []
    name = str(d.get("game") or "").strip()
    old_tid = str(d.get("title_id") or "").strip()
    old_cid = str(d.get("content_id") or "").strip()
    cid = content_id(old_cid, old_tid, name, file_name)
    tid = (old_tid.upper() if TITLE_ID_FULL.fullmatch(old_tid.upper()) else
           title_id(old_tid, cid, name, file_name))
    if tid and tid != old_tid:
        changes.append(f"title id {old_tid or '(empty)'} -> {tid}")
    if cid and tid and tid not in cid:
        changes.append(f"content id {cid} is for another game - removed")
        cid = ""
    elif cid and cid != old_cid:
        changes.append(f"content id -> {cid}")
    old_ver = str(d.get("version") or "").strip()
    ver = version(old_ver, tid)
    if ver != str(d.get("version") or ""):
        changes.append(f"version {old_ver or '(empty)'} -> {ver}")
    proc = str(d.get("process") or "").strip() or "eboot.bin"
    if proc != str(d.get("process") or ""):
        changes.append(f"process -> {proc}")
    if not name or name.upper() in (tid, cid, old_tid.upper()):
        # a name that is just an id: keep it, the user can rename (the console does not report titles)
        name = name or tid or cid or "game"
    if name != str(d.get("game") or ""):
        changes.append(f"name -> {name}")
    d.update({"game": name, "title_id": tid or old_tid, "version": ver, "process": proc})
    if cid:
        d["content_id"] = cid
    else:
        d.pop("content_id", None)
    return d, changes


@dataclass
class RunningGame:
    """What the console reports about the game in front (ps5debug-NG 0xBDDD0006)."""
    pid: int
    title_id: str
    content_id: str
    process: str
    version: str

    @property
    def ok(self) -> bool:
        return self.pid > 0 and bool(self.title_id)


def from_console(client, pid: int = 0) -> RunningGame:
    """Title id, content id and app version of the running game, like Reaper Studio reads them.
    pid: the attached process - when given and it is not the game in front, its title / content id
    come from proc info and the version is left empty (the console only reports the front game's)."""
    fg = None
    try:
        fg = client.foreground_app()
    except Exception:
        fg = None                                   # older payload without 0xBDDD0006
    if fg is not None and fg.pid and (not pid or fg.pid == pid):
        tid = title_id(fg.titleid, fg.contentid)
        return RunningGame(fg.pid, tid, content_id(fg.contentid), fg.name or "eboot.bin",
                           version(fg.app_ver, tid))
    if pid:
        info = client.proc_info(pid)
        tid = title_id(info.titleid, info.contentid)
        return RunningGame(pid, tid, content_id(info.contentid), info.name or "eboot.bin", "")
    return RunningGame(0, "", "", "", "")


def library_path(folder, tid: str, ver: str, name: str = "", suffix: str = ""):
    """A free file in the cheats folder named by the standard: <TITLEID>_<VERSION>[_suffix].json,
    then _2, _3 ... when taken."""
    from pathlib import Path  # noqa: PLC0415
    stem = file_stem(tid, ver, name or "game")
    if suffix:
        stem += "_" + re.sub(r"[^A-Za-z0-9_.-]+", "_", suffix).strip("_")
    path, n = Path(folder) / f"{stem}.json", 2
    while path.exists():
        path, n = Path(folder) / f"{stem}_{n}.json", n + 1
    return path


def ask_console(app, done) -> None:
    """GUI helper: read the game in front on a worker thread, then call done(RunningGame | None, error)
    on the UI thread.  Falls back to the attached process when the payload has no foreground query."""
    client = getattr(app, "client", None)
    if client is None or not getattr(client, "connected", False):
        done(None, "not connected to the console - connect first, with the game running")
        return
    try:
        pid = int(app._pid())
    except Exception:
        pid = 0

    def work() -> None:
        try:
            run = from_console(client, 0)
            if not run.ok and pid:
                run = from_console(client, pid)
            err = None if run.ok else "no game is running on the console"
        except Exception as exc:              # noqa: BLE001 - shown to the user
            run, err = None, str(exc)
        app.root.after(0, lambda: done(run if run is not None and run.ok else None, err))

    app._run_bg(work, "Reading the game's title id and version...")
