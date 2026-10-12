"""Array-of-bytes (AOB) signatures: parse, format, build from code, find in a process.

Pattern text:  "48 8B 05 ?? ?? ?? ?? 48 85 C0"   (?? / ? / * = any byte; also "488B05????")
"""

from __future__ import annotations

import re
import struct
from typing import Callable, Optional

M64 = (1 << 64) - 1


class AobError(Exception):
    pass


def parse(text: str) -> tuple[bytes, bytes]:
    """-> (pattern, mask) ; mask byte 1 = must match, 0 = wildcard."""
    t = text.strip().replace(",", " ").replace("-", " ")
    toks = t.split()
    if len(toks) == 1 and len(toks[0]) > 2:
        h = toks[0]
        toks = [h[i:i + 2] for i in range(0, len(h), 2)]
    pat, mask = bytearray(), bytearray()
    for tok in toks:
        if set(tok) <= {"?", "*"}:
            pat.append(0)
            mask.append(0)
        else:
            try:
                pat.append(int(tok, 16) & 0xFF)
            except ValueError:
                raise AobError(f"bad AOB byte '{tok}'") from None
            mask.append(1)
    if not pat:
        raise AobError("empty AOB pattern")
    while mask and mask[-1] == 0:        # trailing wildcards add nothing
        pat.pop()
        mask.pop()
    if not any(mask):
        raise AobError("the AOB pattern needs at least one fixed byte")
    return bytes(pat), bytes(mask)


def fmt(pattern: bytes, mask: bytes) -> str:
    return " ".join(f"{b:02X}" if m else "??" for b, m in zip(pattern, mask))


def from_b64(pattern_b64: str, mask_b64: Optional[str]) -> tuple[bytes, bytes]:
    import base64
    pat = base64.b64decode(pattern_b64)
    mask = base64.b64decode(mask_b64) if mask_b64 else b"\x01" * len(pat)
    mask = bytes(1 if m == 1 else 0 for m in mask[: len(pat)]).ljust(len(pat), b"\x01")
    return pat, mask


# ------------------------------------------------------------ signatures from code
def insn_mask(ins) -> bytes:
    """Mask for one instruction: the 4 bytes of a rel32 branch target or a RIP-relative
    displacement are wildcards (they change whenever the game is rebuilt)."""
    raw = bytes(ins.raw)
    mask = bytearray(b"\x01" * len(raw))
    end = ins.addr + len(raw)
    for target in (ins.target, ins.ripref):
        if target is None:
            continue
        rel = (target - end) & 0xFFFFFFFF
        needle = struct.pack("<I", rel)
        i = raw.rfind(needle)
        if i > 0:
            for k in range(i, i + 4):
                mask[k] = 0
    return bytes(mask)


def signature(insns: list, start: int, max_len: int = 64) -> list[tuple[bytes, bytes]]:
    """Growing candidate signatures starting at insns[start] (whole instructions), shortest first."""
    out: list[tuple[bytes, bytes]] = []
    pat, mask = b"", b""
    prev = None
    for ins in insns[start:]:
        if not ins.raw or (prev is not None and ins.addr != prev.addr + prev.size):
            break
        prev = ins
        pat += bytes(ins.raw)
        mask += insn_mask(ins)
        if len(pat) > max_len:
            break
        if sum(mask) >= 5:
            out.append((pat, mask))
    return out


# ------------------------------------------------------------ regions / scanning
def main_module_name(maps) -> str:
    exe = [m for m in maps if m.prot & 4]
    if not exe:
        raise AobError("no executable mapping in the process")
    return min(exe, key=lambda m: m.start).name


def regions(maps, module: str = "main", code_only: bool = True) -> list[tuple[int, int]]:
    """(start, length) ranges to scan: the executable (or all readable) mappings of a module.
    module: 'main' (the game executable), a mapping name, or '*' for every mapping."""
    section = None
    if "#" in module:                          # "main#1" = only the 2nd mapping (section) of the module
        module, _, sec = module.partition("#")
        section = int(sec.strip() or "0", 0)
    if module == "*":
        sel = list(maps)
    else:
        name = main_module_name(maps) if module.lower() in ("", "main", "eboot", "executable") else module
        sel = [m for m in maps if m.name == name] or [m for m in maps if name.lower() in m.name.lower()]
    if section is not None:
        secs = sorted(sel, key=lambda m: m.start)
        sel = [secs[section]] if section < len(secs) else []
    sel = [m for m in sel if (m.prot & 4 if code_only else m.prot & 1)]
    out: list[tuple[int, int]] = []
    for m in sorted(sel, key=lambda m: m.start):
        a, n = m.start, m.end - m.start
        while n > 0:
            k = min(n, 0xFFFF0000)
            out.append((a, k))
            a += k
            n -= k
    if not out:
        raise AobError(f"module '{module}' has no {'executable' if code_only else 'readable'} mapping")
    return out


def find_all(client, pid: int, ranges: list[tuple[int, int]], pattern: bytes, mask: bytes,
             limit: int = 32) -> list[int]:
    hits: list[int] = []
    for a, n in ranges:
        hits += client.scan_aob_all(pid, a, n, pattern, mask, limit)
        if len(hits) >= limit:
            break
    return hits[:limit]


def find(client, pid: int, ranges: list[tuple[int, int]], pattern: bytes, mask: bytes, index: int = 1) -> int:
    """index-th match over all ranges (1-based); 0 if there are fewer matches."""
    seen = 0
    for a, n in ranges:
        if index == 1:
            r = client.scan_aob(pid, a, n, pattern, mask, 1)
            if r:
                return r
            continue
        hits = client.scan_aob_all(pid, a, n, pattern, mask, min(255, index - seen))
        if seen + len(hits) >= index:
            return hits[index - seen - 1]
        seen += len(hits)
    return 0


def unique_signature(client, pid: int, maps, insns: list, start: int,
                     log: Optional[Callable[[str], None]] = None) -> tuple[str, int]:
    """Shortest signature at insns[start] that occurs exactly once in the main executable.
    -> (pattern text, match count of the returned pattern)"""
    rng = regions(maps, "main")
    last = None
    for pat, mask in signature(insns, start):
        hits = find_all(client, pid, rng, pat, mask, 2)
        last = (pat, mask, len(hits))
        if log:
            log(f"  {len(pat):2d} bytes -> {len(hits)} match(es)")
        if len(hits) == 1:
            return fmt(pat, mask), 1
    if last is None:
        raise AobError("no instructions to build a signature from")
    return fmt(last[0], last[1]), last[2]
