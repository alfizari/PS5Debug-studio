"""Pointer scanner (Cheat Engine style) - the engine, no UI.

1. build_map():  every 8-byte value in the game's writable memory that points into writable memory.
   The console does the scanning (turbo scan, 8-byte "between lowest and highest data address",
   8-byte aligned), so only the hits cross the network.  Without turbo scan it falls back to
   reading the regions.
2. search():     walk backwards from the target with numpy (sorted values + binary search, one level
   at a time) and keep the chains whose first pointer sits inside a module (eboot.bin, a .prx ...),
   because those survive a restart.
3. resolve():    follow chains on the live game (one bulk read per level) - for live values and
   for "Rescan" (keep only the chains that still lead to the new address).
"""

from __future__ import annotations

import json
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

try:
    import numpy as np
except ImportError:            # reported nicely by the dialog
    np = None

Progress = Optional[Callable[[str, float], None]]      # (message, fraction 0..1 or -1)
Cancel = Optional[Callable[[], bool]]

MODULE_RX = re.compile(r"\.(bin|elf|self|prx|sprx|so)$", re.I)
MAP_FORMAT = "ps5ptrmap/1"
RES_FORMAT = "ps5ptrs/1"


def need_numpy() -> None:
    if np is None:
        raise RuntimeError("the pointer scanner needs numpy - run:  pip install numpy")


class Cancelled(Exception):
    pass


@dataclass
class Region:
    start: int
    end: int
    prot: int
    name: str

    def to_list(self) -> list:
        return [self.start, self.end, self.prot, self.name]


@dataclass
class PointerMap:
    addrs: "np.ndarray"            # uint64, where each pointer is stored
    vals: "np.ndarray"             # uint64, what it points to
    regions: list[Region]          # the process maps when the map was made
    pid: int = 0
    title: str = ""
    created: float = field(default_factory=time.time)
    _sorted: Optional[tuple] = None

    def __len__(self) -> int:
        return int(self.addrs.size)

    def by_value(self) -> tuple["np.ndarray", "np.ndarray"]:
        """(values sorted, their addresses) - built once."""
        if self._sorted is None:
            order = np.argsort(self.vals, kind="stable")
            self._sorted = (self.vals[order], self.addrs[order])
        return self._sorted

    def save(self, path: Path) -> None:
        meta = {"format": MAP_FORMAT, "pid": self.pid, "title": self.title, "created": self.created,
                "regions": [r.to_list() for r in self.regions]}
        with open(path, "wb") as fh:
            np.savez_compressed(fh, addrs=self.addrs, vals=self.vals,
                                meta=np.frombuffer(json.dumps(meta).encode(), dtype=np.uint8))

    @staticmethod
    def load(path: Path) -> "PointerMap":
        need_numpy()
        with np.load(path) as z:
            meta = json.loads(bytes(z["meta"]).decode())
            if meta.get("format") != MAP_FORMAT:
                raise ValueError("not a pointer map file")
            return PointerMap(z["addrs"].astype(np.uint64), z["vals"].astype(np.uint64),
                              [Region(*r) for r in meta["regions"]], meta.get("pid", 0),
                              meta.get("title", ""), meta.get("created", 0.0))


@dataclass
class Chain:
    module: str                    # base module name (as in the process maps)
    base_off: int                  # offset of the first pointer from the module's lowest address
    offsets: tuple[int, ...]       # one per dereference, first applied first

    @property
    def level(self) -> int:
        return len(self.offsets)

    def expr(self) -> str:
        """Cheat / address expression:  [[module(x)+0x10]+0x18]+0x20"""
        e = f"[module({self.module})+0x{self.base_off:X}]"
        for o in self.offsets[:-1]:
            e = f"[{e}+0x{o:X}]"
        last = self.offsets[-1]
        return f"{e}+0x{last:X}" if last else e

    def ce_text(self) -> str:
        """Cheat Engine style:  "eboot.bin"+3A1F28 -> 18 -> 240 -> 10"""
        return f'"{self.module}"+{self.base_off:X} -> ' + " -> ".join(f"{o:X}" for o in self.offsets)

    def to_list(self) -> list:
        return [self.module, self.base_off, list(self.offsets)]

    @staticmethod
    def from_list(d: list) -> "Chain":
        return Chain(str(d[0]), int(d[1]), tuple(int(x) for x in d[2]))


def save_results(path: Path, chains: list[Chain], info: dict) -> None:
    Path(path).write_text(json.dumps({"format": RES_FORMAT, **info, "chains": [c.to_list() for c in chains]}),
                          encoding="utf-8")


def load_results(path: Path) -> tuple[list[Chain], dict]:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    if d.get("format") != RES_FORMAT:
        raise ValueError("not a pointer scan result file")
    info = {k: v for k, v in d.items() if k not in ("format", "chains")}
    return [Chain.from_list(x) for x in d["chains"]], info


# --------------------------------------------------------------------------- helpers
def _merge(iv: Iterable[tuple[int, int]]) -> tuple["np.ndarray", "np.ndarray"]:
    out: list[list[int]] = []
    for a, b in sorted(iv):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    if not out:
        return np.zeros(0, np.uint64), np.zeros(0, np.uint64)
    arr = np.array(out, dtype=np.uint64)
    return arr[:, 0].copy(), arr[:, 1].copy()


def _inside(v: "np.ndarray", starts: "np.ndarray", ends: "np.ndarray") -> "np.ndarray":
    if starts.size == 0:
        return np.zeros(v.shape, bool)
    i = np.searchsorted(starts, v, side="right").astype(np.int64) - 1
    ok = i >= 0
    ic = np.where(ok, i, 0)
    return ok & (v < ends[ic])


MAIN_NAMES = ("executable", "eboot.bin", "eboot")      # ps5debug-NG lists the game's own image as "executable"
MAIN_ALIASES = ("eboot", "eboot.bin", "main", "game", "exe", "executable")


def is_module(name: str) -> bool:
    n = (name or "").strip()
    return bool(n) and (bool(MODULE_RX.search(n)) or n.lower() in MAIN_NAMES)


def _wanted(name: str, want: list[str]) -> bool:
    """Base-module filter: a part of the name, or 'eboot' / 'main' / 'game' for the game's own image."""
    low = name.lower()
    return any(w in low or (w in MAIN_ALIASES and low in MAIN_NAMES) for w in want)


def static_regions(regions: list, want: Optional[list[str]] = None, gap: int = 0x10000,
                   max_extra: int = 2, max_extra_bytes: int = 128 << 20,
                   include_bss: bool = True) -> tuple[list[Region], list[str]]:
    """Regions where a chain may start: every mapping of a module (eboot.bin, *.sprx ...) PLUS the unnamed
    writable regions that directly follow a module's last mapping.  A module's .bss (zero-filled globals,
    where games keep most of their singleton pointers) is usually mapped as a separate anonymous region
    right after the named ones - without this, chains starting in the game's globals are missed.
    Returns (regions labelled with their module name, notes describing what was added)."""
    want = [w.strip().lower() for w in (want or []) if w.strip()]
    out: list[Region] = []
    notes: list[str] = []
    rs = sorted(regions, key=lambda r: r.start)
    cur, prev_end, added, added_bytes = None, 0, 0, 0
    for r in rs:
        if is_module(r.name):
            cur, prev_end, added, added_bytes = r.name, r.end, 0, 0
            if not want or _wanted(r.name, want):
                out.append(Region(r.start, r.end, r.prot, r.name))
            continue
        if (include_bss and cur and r.start - prev_end <= gap and (r.prot & 3) == 3 and not (r.prot & 4)
                and added < max_extra and added_bytes + (r.end - r.start) <= max_extra_bytes):
            added += 1
            added_bytes += r.end - r.start
            prev_end = r.end
            if not want or _wanted(cur, want):
                out.append(Region(r.start, r.end, r.prot, cur))
                label = r.name or "unnamed"
                notes.append(f"{cur}: +{(r.end - r.start) // 1024:,} KB {label} region after it (.bss)")
            continue
        cur = None
    return out, notes


def module_bases(regions: Iterable) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in regions:
        if r.name:
            out[r.name] = min(out.get(r.name, r.start), r.start)
    return out


def data_regions(regions: list[Region], include_readonly: bool = False) -> list[Region]:
    """Where pointers are stored / point to: readable, non-executable, writable (or read-only data)."""
    out = []
    for r in regions:
        if not (r.prot & 1) or (r.prot & 4) or r.end <= r.start:
            continue
        if not (r.prot & 2) and not include_readonly:
            continue
        out.append(r)
    return out


class _TooMany(Exception):
    pass


def _windows(starts, ends, gap: int) -> list[tuple[int, int]]:
    """Data regions grouped into address windows (regions closer than `gap` share one window)."""
    out: list[list[int]] = []
    for a, b in zip(starts.tolist(), ends.tolist()):
        if out and a - out[-1][1] <= gap:
            out[-1][1] = b
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


# --------------------------------------------------------------------------- 1. pointer map
def build_map(cli, pid: int, title: str = "", skip_slow: bool = True, include_readonly: bool = False,
              progress: Progress = None, cancel: Cancel = None, alias: bool = True) -> PointerMap:
    """`cli` should be a connection of its own (the scan blocks it for a while)."""
    need_numpy()

    def say(msg: str, frac: float = -1.0) -> None:
        if progress:
            progress(msg, frac)

    def check() -> None:
        if cancel and cancel():
            raise Cancelled()

    say("reading the memory map...")
    regions = [Region(m.start, m.end, m.prot, m.name) for m in cli.maps(pid)]
    slow: set[int] = set()
    caps = None
    try:
        caps = cli.turbo_caps()
    except Exception:
        caps = None
    if skip_slow and caps is not None:
        try:
            for r in cli.turbo_regions(pid):
                if r.uncached or (r.mbps and r.mbps < 100):
                    slow.add(r.start)
        except Exception:
            pass
    src = [r for r in data_regions(regions, include_readonly) if r.start not in slow]
    if not src:
        raise RuntimeError("no readable data regions in this process")
    t_starts, t_ends = _merge((r.start, r.end) for r in src)
    check()

    addrs_parts: list = []
    vals_parts: list = []
    src_bytes = sum(r.end - r.start for r in src)
    segs = [(r.start, r.end - r.start) for r in src]
    # Game memory is spread out (code low, heaps high), so one "lowest..highest address" range would
    # match almost every number in memory.  Scan each cluster of data regions as its own narrow range.
    windows = _windows(t_starts, t_ends, gap=32 << 20)
    used_turbo = False
    if caps is not None:
        hits = _ConsoleHits(cli, pid, segs, caps, check, say, alias)
        budget = int(src_bytes * 0.6) // 24          # beyond this, reading the memory is cheaper
        got_total = 0
        try:
            for wi, (wlo, whi) in enumerate(windows):
                tag = f"area {wi + 1}/{len(windows)} ({(whi - wlo) / 1048576:,.0f} MB)"
                say(f"console: finding pointers into {tag}...", wi / len(windows))
                av, vv = hits.get(wlo, whi - 1, f"pointers into {tag}")
                got_total += av.size
                if got_total > budget:
                    raise _TooMany(f"more than {budget:,} pointers - reading the memory is faster")
                keep = _inside(vv, t_starts, t_ends)
                addrs_parts.append(av[keep])
                vals_parts.append(vv[keep])
            used_turbo = True
        except Cancelled:
            raise
        except Exception as exc:
            if not cli.connected:
                raise
            say(f"{exc} - reading the memory instead")
            addrs_parts, vals_parts = [], []
        finally:
            hits.close()

    if not used_turbo:
        done, total = 0, src_bytes
        chunk = 16 << 20
        t0 = time.monotonic()
        for r in src:
            a = r.start
            while a < r.end:
                check()
                n = min(chunk, r.end - a)
                try:
                    data = cli.read(pid, a, n)
                except Exception:
                    if not cli.connected:
                        raise
                    a += n
                    done += n
                    continue
                v = np.frombuffer(data[: len(data) // 8 * 8], dtype="<u8")
                keep = _inside(v, t_starts, t_ends)
                idx = np.nonzero(keep)[0].astype(np.uint64)
                addrs_parts.append(np.uint64(a) + idx * np.uint64(8))
                vals_parts.append(v[keep].astype(np.uint64))
                a += n
                done += n
                dt = max(0.001, time.monotonic() - t0)
                rate = done / dt
                eta = (total - done) / rate if rate else 0
                say(f"reading memory: {done / 1048576:,.0f} / {total / 1048576:,.0f} MB  ·  "
                    f"{rate / 1048576:,.0f} MB/s  ·  {eta:,.0f} s left", done / total)

    addrs = np.concatenate(addrs_parts) if addrs_parts else np.zeros(0, np.uint64)
    vals = np.concatenate(vals_parts) if vals_parts else np.zeros(0, np.uint64)
    order = np.argsort(addrs, kind="stable")
    pm = PointerMap(addrs[order], vals[order], regions, pid, title)
    say(f"pointer map: {len(pm):,} pointers", 1.0)
    return pm


# --------------------------------------------------------------------------- 2. backward search
@dataclass
class SearchResult:
    chains: list[Chain]
    truncated: bool
    note: str = ""
    per_level: list[int] = field(default_factory=list)
    module_notes: list[str] = field(default_factory=list)   # regions counted as module .bss


def search(pm: PointerMap, target: int, max_level: int = 5, max_off: int = 0x1000,
           base_modules: Optional[list[str]] = None, max_results: int = 100000,
           max_nodes: int = 4_000_000, progress: Progress = None, cancel: Cancel = None,
           last_off: Optional[int] = None, include_bss: bool = True) -> SearchResult:
    """Chains  module+off -> o1 -> o2 ... -> target.  `base_modules`: names (or parts of names) allowed as
    the base; None = every module.  Each address is used at its lowest level only (like CE's
    'no looping pointers'), which keeps the search from exploding."""
    need_numpy()
    sv, sa = pm.by_value()
    u64 = np.uint64

    # static (base) ranges
    stat, bss_notes = static_regions(pm.regions, base_modules, include_bss=include_bss)
    if not stat:
        raise RuntimeError("no module matches the base module filter")
    s_starts, s_ends = _merge((r.start, r.end) for r in stat)
    region_by_start = sorted(stat, key=lambda r: r.start)
    rs = np.array([r.start for r in region_by_start], dtype=u64)
    bases = module_bases(pm.regions)

    levels = [np.array([target], dtype=u64)]
    static_of_level = [np.zeros(1, bool)]
    edges: list[tuple] = [()]                       # level k: (child idx, parent idx, offset) sorted by child
    visited = np.array([target], dtype=u64)
    frontier_idx = np.array([0], dtype=np.int64)
    note = ""
    per_level = []
    for k in range(1, max_level + 1):
        if cancel and cancel():
            raise Cancelled()
        F = levels[k - 1][frontier_idx]
        if F.size == 0:
            break
        off_k = last_off if (k == 1 and last_off) else max_off     # last offset (into the object) may be bigger
        lo_v = np.where(F > u64(off_k), F - u64(off_k), u64(0))
        lo = np.searchsorted(sv, lo_v, side="left")
        hi = np.searchsorted(sv, F, side="right")
        counts = (hi - lo).astype(np.int64)
        total = int(counts.sum())
        if total == 0:
            break
        if total > max_nodes * 4:
            note = f"stopped at level {k}: {total:,} candidate pointers - lower the max offset or level"
            break
        rep = np.repeat(np.arange(F.size), counts)
        starts = np.repeat(lo.astype(np.int64), counts)
        within = np.arange(total) - np.repeat(np.cumsum(counts) - counts, counts)
        pos = starts + within
        p_addr = sa[pos]
        off = F[rep] - sv[pos]
        # drop addresses already used at a lower level
        vi = np.searchsorted(visited, p_addr)
        seen = (vi < visited.size) & (visited[np.minimum(vi, visited.size - 1)] == p_addr)
        keep = ~seen
        p_addr, off, rep = p_addr[keep], off[keep], rep[keep]
        if p_addr.size == 0:
            break
        U, inv = np.unique(p_addr, return_inverse=True)
        if U.size > max_nodes:
            note = f"stopped at level {k}: {U.size:,} pointers at this level - lower the max offset or level"
            break
        parent = frontier_idx[rep]
        order = np.argsort(inv, kind="stable")
        edges.append((inv[order].astype(np.int64), parent[order], off[order]))
        st = _inside(U, s_starts, s_ends)
        levels.append(U)
        static_of_level.append(st)
        per_level.append(int(U.size))
        visited = np.union1d(visited, U)
        frontier_idx = np.nonzero(~st)[0]
        if progress:
            progress(f"level {k}: {U.size:,} pointers, {int(st.sum()):,} in modules", k / max_level)

    chains, truncated = _enumerate(levels, static_of_level, edges, region_by_start, rs, bases, max_results)
    return SearchResult(chains, truncated, note, per_level, bss_notes)


def _enumerate(levels, static_of_level, edges, region_by_start, rs, bases, max_results: int):
    """Chains from every module (static) node down to the target, shortest first."""
    u64 = np.uint64
    chains: list[Chain] = []
    truncated = False
    for k in range(1, len(levels)):
        st_idx = np.nonzero(static_of_level[k])[0]
        if st_idx.size == 0:
            continue
        for node in st_idx:
            base_addr = int(levels[k][node])
            ri = int(np.searchsorted(rs, u64(base_addr), side="right")) - 1
            mod = region_by_start[ri].name
            base_off = base_addr - bases.get(mod, region_by_start[ri].start)
            # DFS: (level, node, offsets so far)
            stack = [(k, int(node), ())]
            while stack:
                lv, nd, offs = stack.pop()
                ch, par, of = edges[lv]
                a = int(np.searchsorted(ch, nd, side="left"))
                b = int(np.searchsorted(ch, nd, side="right"))
                for j in range(b - 1, a - 1, -1):
                    o = offs + (int(of[j]),)
                    if lv == 1:
                        chains.append(Chain(mod, base_off, o))
                        if len(chains) >= max_results:
                            truncated = True
                            break
                    else:
                        stack.append((lv - 1, int(par[j]), o))
                if truncated:
                    break
            if truncated:
                break
        if truncated:
            break
    return chains, truncated


# --------------------------------------------------------------------------- 2b. targeted search on the console
class _ConsoleHits:
    """'Which 8-byte values in game data lie in [lo, hi]?' answered by the console (turbo scan); only the
    hits are downloaded.  A window the console refuses (too many hits) is split in halves."""

    def __init__(self, cli, pid: int, segs, caps, check, say, alias: bool = True) -> None:
        from ps5debug_client import (TurboScanSession, TS_PARALLEL_COMPARE, TSE_PARALLEL_COMPARE,  # noqa: PLC0415
                                     TS_USE_ALIASING, TSE_ALIASING)
        self.cli, self.pid, self.segs, self.check, self.say = cli, pid, segs, check, say
        self.sess = TurboScanSession(cli, caps)
        self.flags = TS_PARALLEL_COMPARE if caps.has(TSE_PARALLEL_COMPARE) else 0
        if alias and caps.has(TSE_ALIASING):
            self.flags |= TS_USE_ALIASING          # read game memory at DRAM speed (falls back per chunk)
        self.scans = 0
        self.scan_time = 0.0

    def get(self, lo: int, hi: int, label: str, depth: int = 0):
        self.check()
        s = self.sess
        s.pid, s.value_type, s.value_len = self.pid, 6, 8
        t0 = time.monotonic()
        n = s._resident_start(self.pid, self.segs, 6, 4, struct.pack("<QQ", lo, hi), None, 8, self.flags, None)
        self.scans += 1
        self.scan_time += time.monotonic() - t0
        if n is None:
            self._end()
            if depth >= 10 or hi - lo < 0x100:
                raise RuntimeError(f"the console found too many values in 0x{lo:X}..0x{hi:X}")
            mid = lo + (hi - lo) // 2
            a1, v1 = self.get(lo, mid, label, depth + 1)
            a2, v2 = self.get(mid + 1, hi, label, depth + 1)
            return np.concatenate([a1, a2]), np.concatenate([v1, v2])
        parts_a, parts_v, got = [], [], 0
        while got < n:
            self.check()
            blob, k, rec = s.get_raw(got, min(1 << 16, n - got))
            if k == 0:
                break
            arr = np.frombuffer(blob, dtype=np.uint8).reshape(k, rec)
            parts_a.append(arr[:, 0:8].copy().view("<u8").ravel())
            parts_v.append(arr[:, 8:16].copy().view("<u8").ravel())
            got += k
            if n > 200000:
                self.say(f"{label}: downloading {got:,} / {n:,}", -1.0)
        self._end()
        if not parts_a:
            return np.zeros(0, np.uint64), np.zeros(0, np.uint64)
        return np.concatenate(parts_a).astype(np.uint64), np.concatenate(parts_v).astype(np.uint64)

    def _end(self) -> None:
        try:
            self.sess.end()
        except Exception:
            if not self.cli.connected:
                raise

    def close(self) -> None:
        self._end()


def _scan_windows(F: "np.ndarray", max_off: int, max_scans: int) -> list[tuple[int, int]]:
    """[f - max_off, f] for every frontier address, merged; then the closest windows are joined until
    at most `max_scans` remain (fewer console scans, a few more hits to filter on the PC)."""
    lo = np.where(F > np.uint64(max_off), F - np.uint64(max_off), np.uint64(0))
    win: list[list[int]] = []
    for a, b in zip(lo.tolist(), F.tolist()):
        if win and a <= win[-1][1] + 1:
            win[-1][1] = max(win[-1][1], b)
        else:
            win.append([a, b])
    if len(win) > max_scans:
        gaps = sorted(range(len(win) - 1), key=lambda i: win[i + 1][0] - win[i][1], reverse=True)
        cuts = set(gaps[: max_scans - 1])
        merged = [list(win[0])]
        for i in range(1, len(win)):
            if (i - 1) in cuts:
                merged.append(list(win[i]))
            else:
                merged[-1][1] = win[i][1]
        win = merged
    return [(a, b) for a, b in win]


def search_live(cli, pid: int, target: int, max_level: int = 5, max_off: int = 0x1000,
                base_modules: Optional[list[str]] = None, max_results: int = 100000,
                skip_slow: bool = True, include_readonly: bool = False, max_scans: int = 12,
                max_nodes: int = 1_000_000, progress: Progress = None, cancel: Cancel = None,
                alias: bool = True, last_off: Optional[int] = None, include_bss: bool = True) -> SearchResult:
    """Pointer scan without a pointer map: each level asks the console only for the values that point
    just below the addresses found so far.  Downloads kilobytes to a few MB instead of the whole memory."""
    need_numpy()
    u64 = np.uint64

    def say(msg: str, frac: float = -1.0) -> None:
        if progress:
            progress(msg, frac)

    def check() -> None:
        if cancel and cancel():
            raise Cancelled()

    say("reading the memory map...")
    regions = [Region(m.start, m.end, m.prot, m.name) for m in cli.maps(pid)]
    caps = cli.turbo_caps()
    if caps is None:
        raise RuntimeError("targeted scan needs ps5debug-NG turbo scan - use 'Full map' mode instead")
    slow: set[int] = set()
    if skip_slow:
        try:
            for r in cli.turbo_regions(pid):
                if r.uncached or (r.mbps and r.mbps < 100):
                    slow.add(r.start)
        except Exception:
            pass
    src = [r for r in data_regions(regions, include_readonly) if r.start not in slow]
    if not src:
        raise RuntimeError("no readable data regions in this process")
    segs = [(r.start, r.end - r.start) for r in src]

    stat, bss_notes = static_regions(regions, base_modules, include_bss=include_bss)
    if not stat:
        raise RuntimeError("no module matches the base module filter")
    s_starts, s_ends = _merge((r.start, r.end) for r in stat)
    region_by_start = sorted(stat, key=lambda r: r.start)
    rs = np.array([r.start for r in region_by_start], dtype=u64)
    bases = module_bases(regions)

    from ps5debug_client import TSE_POINTER_SCAN  # noqa: PLC0415
    on_console = caps.has(TSE_POINTER_SCAN)      # modified payload: one pass per level, matching on the console
    hits = None if on_console else _ConsoleHits(cli, pid, segs, caps, check, say, alias)
    passes = 0
    levels = [np.array([target], dtype=u64)]
    static_of_level = [np.zeros(1, bool)]
    edges: list[tuple] = [()]
    visited = np.array([target], dtype=u64)
    frontier_idx = np.array([0], dtype=np.int64)
    note = ""
    per_level: list[int] = []
    t0 = time.monotonic()
    try:
        for k in range(1, max_level + 1):
            check()
            F_all = levels[k - 1]
            F_idx = frontier_idx[np.argsort(F_all[frontier_idx], kind="stable")]
            F = F_all[F_idx]
            if F.size == 0:
                break
            off_k = last_off if (k == 1 and last_off) else max_off     # last offset (into the object) may be bigger
            if on_console:
                label = f"level {k}/{max_level}: console pass"
                say(f"{label}  ({F.size:,} address(es) to reach)", (k - 1) / max_level)
                kk = k

                def prog(done: int, total: int, kk=kk, label=label) -> None:
                    say(f"{label}: {done / 1048576:,.0f} / {total / 1048576:,.0f} MB",
                        (kk - 1 + (done / total if total else 0)) / max_level)
                try:
                    blob, _n, _scanned, status = cli.ptrscan_level(pid, segs, F.astype("<u8").tobytes(), off_k,
                                                                   alias, prog)
                except Exception as exc:
                    if not cli.connected:
                        raise
                    # the payload refused (its reason is in the Kernel log tab): use the turbo-scan route
                    say(f"payload pointer scan refused ({exc}) - using turbo scans instead "
                        "(the reason is in the Kernel log tab)")
                    note = f"payload pointer scan refused: {exc} - see the Kernel log tab"
                    on_console = False
                    hits = _ConsoleHits(cli, pid, segs, caps, check, say, alias)
                    blob, status = None, 0
                passes += 1
                if status == 1:
                    raise Cancelled()
                if status == 2:
                    note = f"level {k}: the console stopped at its hit limit - lower the max offset"
                if blob is not None:
                    arr = np.frombuffer(blob, dtype="<u8").reshape(-1, 2)
                    p_addr, p_val = arr[:, 0].astype(u64), arr[:, 1].astype(u64)
            if not on_console:
                wins = _scan_windows(F, off_k, max_scans)
                pa, pv = [], []
                for wi, (wlo, whi) in enumerate(wins):
                    label = f"level {k}/{max_level}, console scan {wi + 1}/{len(wins)}"
                    say(f"{label}  ({F.size:,} address(es) to reach)", (k - 1 + wi / len(wins)) / max_level)
                    a, v = hits.get(wlo, whi, label)
                    pa.append(a)
                    pv.append(v)
                p_addr = np.concatenate(pa) if pa else np.zeros(0, u64)
                p_val = np.concatenate(pv) if pv else np.zeros(0, u64)
            # exact: every frontier address f with  p_val <= f <= p_val + max_off
            lo_i = np.searchsorted(F, p_val, side="left")
            hi_i = np.searchsorted(F, p_val + u64(off_k), side="right")
            counts = (hi_i - lo_i).astype(np.int64)
            total = int(counts.sum())
            if total == 0:
                break
            rep = np.repeat(np.arange(p_addr.size), counts)
            within = np.arange(total) - np.repeat(np.cumsum(counts) - counts, counts)
            fpos = np.repeat(lo_i.astype(np.int64), counts) + within
            c_addr = p_addr[rep]
            off = F[fpos] - p_val[rep]
            parent = F_idx[fpos]
            vi = np.searchsorted(visited, c_addr)
            seen = (vi < visited.size) & (visited[np.minimum(vi, visited.size - 1)] == c_addr)
            keep = ~seen
            c_addr, off, parent = c_addr[keep], off[keep], parent[keep]
            if c_addr.size == 0:
                break
            U, inv = np.unique(c_addr, return_inverse=True)
            order = np.argsort(inv, kind="stable")
            edges.append((inv[order].astype(np.int64), parent[order], off[order]))
            st = _inside(U, s_starts, s_ends)
            levels.append(U)
            static_of_level.append(st)
            per_level.append(int(U.size))
            visited = np.union1d(visited, U)
            frontier_idx = np.nonzero(~st)[0]
            say(f"level {k}: {U.size:,} pointer(s), {int(st.sum()):,} in modules", k / max_level)
            if frontier_idx.size > max_nodes and k < max_level:
                note = (f"stopped after level {k}: {frontier_idx.size:,} pointers to follow (limit {max_nodes:,}) - "
                        "lower 'other offsets', or raise 'max pointers per level'")
                break
    finally:
        if hits is not None:
            hits.close()
    chains, truncated = _enumerate(levels, static_of_level, edges, region_by_start, rs, bases, max_results)
    dt = time.monotonic() - t0
    info = (f"{passes} console pass(es) (payload pointer scan), {dt:.0f}s" if on_console
            else f"{hits.scans if hits else 0} console scan(s), {dt:.0f}s")
    return SearchResult(chains, truncated, (note + "  ·  " if note else "") + info, per_level, bss_notes)


# --------------------------------------------------------------------------- 3. live resolve / rescan
def resolve(cli, pid: int, chains: list[Chain], maps=None, batch: int = 4000) -> list[Optional[int]]:
    """Final address of every chain on the live game (None = broken).  One bulk read per level."""
    if maps is None:
        maps = cli.maps(pid)
    bases = module_bases(maps)
    lower = {k.lower(): v for k, v in bases.items()}
    cur: list[Optional[int]] = []
    for c in chains:
        b = bases.get(c.module, lower.get(c.module.lower()))
        cur.append(None if b is None else b + c.base_off)
    depth = max((c.level for c in chains), default=0)
    for step in range(depth):
        idx = [i for i, c in enumerate(chains) if cur[i] is not None and step < c.level]
        for s in range(0, len(idx), batch):
            part = idx[s : s + batch]
            datas = cli.read_multi(pid, [(cur[i], 8) for i in part])
            for i, d in zip(part, datas):
                p = int.from_bytes(d[:8], "little") if len(d) >= 8 else 0
                cur[i] = (p + chains[i].offsets[step]) & 0xFFFFFFFFFFFFFFFF if p else None
    return cur
