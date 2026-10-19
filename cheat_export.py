"""Export this tool's cheats to the formats other cheat menus load: GoldHEN .json, .shn and .mc4.

Those formats can only describe one thing: "write these bytes at this offset of the game
executable when the cheat is on, write these other bytes when it is off".  So a cheat exports
only when every step is a fixed patch of the game executable - no code caves allocated at run
time, no AOB scans, pointers, hooks, calls, parameters or Python.  `analyze` checks each cheat
and says why one cannot be exported; nothing is ever half-converted.

Code caves (hook + @buffers) export too when a CavePlan gives free space inside the game executable:
the cave code is assembled at that fixed offset (relative jumps, so it works wherever the game
loads), written as a line whose off value is the same code (it stays, unused, when the cheat is
off), and the hook site becomes "jmp cave" with the original bytes as its off value.  The cheat
then is plain lines, like hand-made GoldHEN code-cave cheats.  @buffers the code only reads go into
the code area; buffers it writes need a writable area (CavePlan.data_off).

Rules (same as the files in the GoldHEN cheat repository and ReverseTelnet's AIO converter):
  * offsets are relative to the game executable (section 0 unless the cheat uses main#N);
    GoldHEN .json has no section field, so it needs section 0
  * every line has an on and an off value of the same length (off = the original bytes)
  * .shn / .mc4 cheats are on/off (checkbox) only; .json also has "button" (run once)
  * title id CUSA##### / PPSA#####, version 01.05 (PS4) / 01.000.000 (PS5), file name TITLEID_VERSION.ext
  * .mc4 = the .shn text, PKCS#7 padded, AES-256-CBC with the public mc4 key, base64
  * .ShnExt = raw-deflated JSON; every cheat is one encrypted "patch entry" whose lines are
    fixed offsets from the executable with their code as assembly text (or nop:N).  The keys
    live only in the private shnext_decryptor.py (not shipped); without it this format is off.
"""

from __future__ import annotations

import base64
import json
import re
import sys
import zlib
from dataclasses import dataclass, field
from typing import Callable, Optional
from xml.sax.saxutils import escape, quoteattr

import cheats as cheats_mod
from aes_cbc import cbc_encrypt
from cheat_formats import MC4_IV, MC4_KEY

FORMATS = {
    "shn": ("SHN cheat (.shn)", ".shn"),
    "mc4": ("MC4 cheat (.mc4, encrypted SHN)", ".mc4"),
    "json": ("GoldHEN cheat JSON (.json)", ".json"),
    "shnext": ("ShnExt cheat (.ShnExt, encrypted)", ".ShnExt"),
}


def shnext_module():
    """-> (module, "") or (None, why).  The private ShnExt module holds the keys; it is looked up
    next to the tool and in cheat_player/ (and bundled into the exe when it is present at build)."""
    try:
        import shnext_decryptor as m            # noqa: PLC0415
    except Exception:
        try:
            from app_paths import APP_DIR       # noqa: PLC0415
            for d in (APP_DIR, APP_DIR / "cheat_player"):
                if (d / "shnext_decryptor.py").exists() and str(d) not in sys.path:
                    sys.path.append(str(d))
            import shnext_decryptor as m        # noqa: PLC0415
        except Exception as exc:
            return None, f"the private ShnExt module (shnext_decryptor.py) is not available ({exc})"
    if not all(hasattr(m, f) for f in ("encrypt_entry", "encrypt_process_name", "key_iv")):
        return None, "shnext_decryptor.py is an older copy without the ShnExt writer - update it"
    return m, ""
TITLE_RE = re.compile(r"^(CUSA|PPSA)\d{5}$")
VERSION_RE = re.compile(r"^\d{2}\.\d{2}$")
MAIN_NAMES = ("", "main", "eboot.bin", "eboot", "executable")
_IGNORED_OPS = ("log", "sleep")                 # no effect on memory: dropped silently
_DROPPED_OPS = ("check",)                       # dropped with a warning

_SPAN = 1 << 40                                # distance between made-up sections (PS4 offsets can pass 4 GB)
_B1, _B2 = 1 << 56, (1 << 56) + 0x2345_6000_0000 * 1024   # two made-up load addresses


class _NotStatic(Exception):
    pass


@dataclass
class Line:
    section: int
    offset: int
    on: bytes
    off: Optional[bytes]        # None = still needs the original bytes
    addr: str                   # the cheat's address expression (to read the original bytes)
    what: str                   # step description for messages
    absolute: bool = False      # offset is the real address (<Absolute>True</Absolute>)


@dataclass
class Report:
    cheat: object
    lines: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    rich: bool = False          # ShnExt: hooks / AOBs / caves - valid without fixed byte lines
    summary: str = ""           # ShnExt: what the patch holds ("1 AOB, 1 hook, 1 input")

    @property
    def ok(self) -> bool:
        return (not self.errors and (bool(self.lines) or self.rich)
                and all(ln.off is not None for ln in self.lines))

    def missing_off(self) -> list:
        return [ln for ln in self.lines if ln.off is None]


class _StaticRT(cheats_mod.Runtime):
    """Evaluates addresses / values with a made-up load address - anything that needs the running
    game (buffers, pointers, variables, other modules) raises _NotStatic."""

    def __init__(self, base: int, process: str) -> None:
        super().__init__(None, None, 0, None, lambda m: None, [])
        self.base = base
        self.names = {n.lower() for n in MAIN_NAMES} | ({process.lower()} if process else set())

    def module_base(self, name: str) -> int:
        n, _, sec = name.partition("#")
        if n.strip().lower() not in self.names:
            raise _NotStatic(f"uses another module ({n.strip()}) - these formats only patch the game executable")
        try:
            s = int(sec.strip() or "0", 0)
        except ValueError:
            raise _NotStatic(f"bad section in module({name})") from None
        return self.base + s * _SPAN

    def read_u64(self, addr: int) -> int:
        raise _NotStatic("follows a pointer ([...]) - the address changes every run")

    def buffer(self, name: str):
        raise _NotStatic(f"uses the buffer @{name}, which only exists while this tool runs the cheat")


def _addr(rts, expr) -> tuple[int, int]:
    """-> (section, offset); section -1 = an absolute address (offset is the address)"""
    try:
        a1, a2 = (rt.ev(expr) for rt in rts)
    except _NotStatic:
        raise
    except Exception as exc:
        msg = str(exc)
        if "variable" in msg:
            raise _NotStatic("uses a variable / parameter ($...) - these formats have no inputs") from None
        if "rax" in msg or "token" in msg:
            raise _NotStatic(f"address {expr!r} is not a fixed offset") from None
        raise _NotStatic(f"bad address {expr!r}: {exc}") from None
    if a1 == a2:                                   # a plain number: GoldHEN "Absolute" line
        return -1, a1
    if a1 - a2 != _B1 - _B2:
        raise _NotStatic(f"address {expr!r} is not module(main)+offset (an absolute address changes every run)")
    rel = a1 - _B1
    if -_SPAN < rel < 0:                           # e.g. FFFFFFFFFFC04000: a cave just before the executable
        return 0, rel & 0xFFFF_FFFF_FFFF_FFFF
    if rel < 0:
        raise _NotStatic(f"address {expr!r} is before the start of the game executable")
    return rel // _SPAN, rel % _SPAN


def _value(rts, s: dict) -> bytes:
    op = s.get("op")
    try:
        if op == "asmpatch":
            import asmgen
            outs = []
            for rt in rts:
                a = rt.ev(s["addr"])
                outs.append(asmgen.assemble(asmgen.substitute(str(s["asm"]), rt.ev), a))
        else:
            if str(s.get("type", "")).lower() in ("utf8", "utf-8", "string", "utf16", "utf16le", "utf-16le") \
                    and re.search(r"\{\w+\}", str(s.get("value", ""))):
                raise _NotStatic("text uses a {parameter} - these formats have no inputs")
            outs = [rt.encode(s["type"], s["value"], bool(s.get("nul", False))) for rt in rts]
    except _NotStatic:
        raise
    except Exception as exc:
        msg = str(exc)
        if "variable" in msg:
            raise _NotStatic("value uses a variable / parameter ($...) - these formats have no inputs") from None
        raise _NotStatic(f"cannot build the bytes: {exc}") from None
    if outs[0] != outs[1]:
        raise _NotStatic("the bytes depend on where the game is loaded (an absolute address in the value / "
                         "asm) - use a RIP-relative or relative form instead")
    if not outs[0]:
        raise _NotStatic("writes zero bytes")
    return outs[0]


@dataclass
class CavePlan:
    """Where code caves go when exporting to .shn / .mc4 / GoldHEN .json: offsets from the start of the
    game executable (module(main)+offset - the numbers the tool shows; nothing to subtract)."""
    code_off: Optional[int] = None      # free space in the executable's code (00 / CC padding)
    data_off: Optional[int] = None      # writable space for @buffers the code writes
    code_free: Optional[int] = None     # bytes known to be free at code_off (from "Find free space")
    data_free: Optional[int] = None
    used_code: int = 0                  # filled while analyzing the cheats, in order
    used_data: int = 0

    def reset(self) -> None:
        self.used_code = self.used_data = 0


_WRITE_SKIP = ("cmp", "test", "push", "ucomiss", "ucomisd", "comiss", "comisd", "bt", "prefetch")


def _writes_buffer(asm: str, name: str) -> bool:
    """Does an instruction use @name in its FIRST operand as memory (a store)?"""
    pat = re.compile(r"@" + re.escape(name) + r"\b")
    for line in str(asm).split("\n"):
        body = line.split(";", 1)[0].split("//", 1)[0].strip()
        m = re.match(r"(?:[A-Za-z_][\w.]*:\s*)?([A-Za-z][\w.]*)\s+(.*)", body)
        if not m or m.group(1).lower().startswith(_WRITE_SKIP):
            continue
        ops, depth, first = m.group(2), 0, ""
        for ch in ops:                                  # the first operand (commas inside [] do not count)
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
            elif ch == "," and depth == 0:
                break
            first += ch
        if "[" in first and pat.search(first):
            return True
    return False


def _param_defaults(cheat) -> dict:
    out = {}
    for p in cheat.params or []:
        if not isinstance(p, dict):
            continue
        t, d = str(p.get("type", "u32")).lower(), p.get("default", 0)
        try:
            if t in ("f32", "f64"):
                import struct
                out[p["name"]] = struct.unpack("<I", struct.pack("<f", float(d)))[0] if t == "f32" \
                    else struct.unpack("<Q", struct.pack("<d", float(d)))[0]
            else:
                out[p["name"]] = int(str(d or 0), 0) & 0xFFFF_FFFF_FFFF_FFFF
        except (TypeError, ValueError):
            out[p["name"]] = 0
    return out


def _static_caves(rts, cheat, cave: CavePlan, r: "Report") -> list:
    """hook / alloc steps -> fixed lines inside the executable (see the module doc).  Returns the
    lines; problems go to r.errors."""
    import asmgen
    import codecave
    steps = [s for s in cheat.steps if isinstance(s, dict)]
    hooks = [s for s in steps if str(s.get("op", "")).lower() == "hook"]
    allocs = [s for s in steps if str(s.get("op", "")).lower() == "alloc"]
    if not hooks and not allocs:
        return []
    if cave.code_off is None:
        r.errors.append("uses a code cave - set 'Code caves at module(main)+0x...' below (free space in the "
                        "game executable)")
        return []
    defaults = _param_defaults(cheat)
    used_params = set()
    lines, bufs = [], {}
    asm_all = "\n".join(str(h.get("asm", "")) for h in hooks)

    def place(size: int, writable: bool) -> Optional[int]:
        size = (size + 15) & ~15
        if writable:
            if cave.data_off is None:
                return None
            off = cave.data_off + cave.used_data
            cave.used_data += size
            return off
        off = ((cave.code_off + cave.used_code) + 15) & ~15
        cave.used_code = off - cave.code_off + size
        return off

    rt = rts[0]
    for a in allocs:
        name = str(a.get("name", ""))
        try:
            size = int(rt.ev(a.get("size", 16))) if not str(a.get("size", "")).strip().startswith("$") \
                else defaults.get(str(a["size"]).strip()[1:], 16)
        except Exception:
            size = 16
        init = b""
        ini = a.get("init") or {}
        if ini:
            val = ini.get("value", "")
            if isinstance(val, str) and val.strip().startswith("$") and val.strip()[1:] in defaults:
                used_params.add(val.strip()[1:])
                pdef = next((p.get("default") for p in cheat.params if p.get("name") == val.strip()[1:]), 0)
                val = pdef
            try:
                init = rt.encode(ini.get("type", "u64"), val, False)
            except Exception as exc:
                r.errors.append(f"buffer @{name}: start value {val!r}: {exc}")
                continue
        size = max(size, len(init), 1)
        writes = _writes_buffer(asm_all, name)
        off = place(size, writes)
        if off is None:
            r.errors.append(f"buffer @{name} is written by the cave code - give a writable 'data' location "
                            "(memory the game does not use), or keep the value in a register")
            continue
        bufs[name] = off
        data = init.ljust(size, b"\0")
        lines.append(Line(0, off, data, data, f"module(main)+0x{off:X}", f"@{name} ({size} bytes)"))

    def resolver(base_rt, base):
        def res(expr: str) -> int:
            e = str(expr)
            for n, o in bufs.items():
                e = re.sub(r"@" + re.escape(n) + r"\b", f"0x{base + o:X}", e)
            bad = re.search(r"@([A-Za-z_]\w*)", e)
            if bad:
                raise _NotStatic(f"uses @{bad.group(1)}, which no alloc step of this cheat creates")

            def dollar(m):
                used_params.add(m.group(1))
                if m.group(1) not in defaults:
                    raise _NotStatic(f"uses ${m.group(1)}, which is not an input of this cheat")
                return f"0x{defaults[m.group(1)]:X}"
            e = re.sub(r"\$([A-Za-z_]\w*)", dollar, e)
            return base_rt.ev(e)
        return res

    for h in hooks:
        name = str(h.get("name") or "hook")
        try:
            sec, site = _addr(rts, h["addr"])
        except _NotStatic as exc:
            if "variable" in str(exc):
                r.errors.append(f"hook {name}: found by AOB at run time - these formats need a fixed offset: in "
                                "the Code cave window untick 'Locate by AOB' and save again (ShnExt keeps AOBs)")
            else:
                r.errors.append(f"hook {name}: {exc}")
            continue
        if sec != 0:
            r.errors.append(f"hook {name}: the hook address must be module(main)+offset")
            continue
        o = str(h.get("orig", "")).strip()
        if o.lower() == "auto":
            orig, n = None, int(h.get("length", 5))
        else:
            try:
                orig = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", o))
            except ValueError:
                r.errors.append(f"hook {name}: bad 'orig' bytes")
                continue
            n = len(orig)
        if n < codecave.JMP_NEAR:
            r.errors.append(f"hook {name}: {n} byte(s) replaced, a jump needs 5")
            continue
        outs = []
        start = ((cave.code_off + cave.used_code) + 15) & ~15
        try:
            for base_rt, base in ((rts[0], _B1), (rts[1], _B2)):
                body = codecave.assemble_at(str(h.get("asm", "")), base + start, resolver(base_rt, base))
                end = base + start + len(body)
                rel = (base + site + n) - (end + 5)
                outs.append(body + b"\xE9" + rel.to_bytes(4, "little", signed=True))
        except _NotStatic as exc:
            r.errors.append(f"hook {name}: {exc}")
            continue
        except (asmgen.AsmError, codecave.CaveError, OverflowError) as exc:
            r.errors.append(f"hook {name}: cannot assemble the cave ({exc})")
            continue
        if outs[0] != outs[1]:
            r.errors.append(f"hook {name}: the cave code holds an absolute address (e.g. mov rax, @buf or a "
                            "module address as a number) - use a RIP-relative form like [rip:@buf] / lea instead")
            continue
        code = outs[0]
        cave.used_code = start - cave.code_off + len(code)
        lines.append(Line(0, start, code, code, f"module(main)+0x{start:X}", f"cave {name} ({len(code)} bytes)"))
        jmp = b"\xE9" + (start - (site + 5)).to_bytes(4, "little", signed=True) + b"\x90" * (n - 5)
        lines.append(Line(0, site, jmp, orig, str(h["addr"]), f"hook {name} -> cave +0x{start:X}"))
    if cave.code_free is not None and cave.used_code > cave.code_free:
        r.errors.append(f"the code caves need {cave.used_code} bytes, the free space found is {cave.code_free}")
    if cave.data_free is not None and cave.used_data > cave.data_free:
        r.errors.append(f"the buffers need {cave.used_data} bytes, the data space given is {cave.data_free}")
    if used_params:
        r.warnings.append("inputs are fixed at their defaults (these formats cannot ask): " +
                          ", ".join(f"{n}={next((p.get('default') for p in cheat.params if p.get('name') == n), '?')}"
                                    for n in sorted(used_params)))
    r.summary = f"cave at +0x{cave.code_off:X}" if hooks else ""
    return lines


def _desc(s: dict) -> str:
    return f"{s.get('op')} {s.get('addr', '')}".strip()


def _analyze_shnext(game, cheat, items: Optional[dict]) -> Report:
    """ShnExt keeps AOBs, hooks, caves, data and inputs (shnext_model).  Fixed-offset sites need the
    game's original bytes: each one is a Line whose off the dialog reads from the game."""
    import shnext_model
    r = Report(cheat, rich=True)
    wanted: list[tuple[str, int]] = []

    def read(expr: str, n: int):
        wanted.append((expr, n))
        return None
    _patch, errs = shnext_model.cheat_to_reap(cheat, 0, game.author or "", items, read, game.process or "eboot.bin")
    r.errors = [e for e in errs if "needs the game's original bytes" not in e]
    ops = [str(s.get("op", "")).lower() for s in cheat.steps if isinstance(s, dict)]
    parts = [(ops.count("aob"), "AOB"), (ops.count("hook"), "hook"),
             (ops.count("asmpatch") + ops.count("write") + ops.count("patch"), "patch"),
             (ops.count("code"), "code block"), (len(cheat.params or []), "input")]
    r.summary = ", ".join(f"{n} {w}{'s' if n > 1 else ''}" for n, w in parts if n)
    for expr, n in wanted:
        r.lines.append(Line(0, 0, b"\0" * n, None, expr, f"original bytes at {expr}"))
    return r


def analyze(game, cheat, fmt: str, items: Optional[dict] = None, cave: Optional[CavePlan] = None) -> Report:
    """Can `cheat` be written as `fmt` ('shn' / 'mc4' / 'json')?  Lines whose off value must come
    from the game (patch / asmpatch, or a write without an off step) get off=None."""
    if fmt == "shnext":
        return _analyze_shnext(game, cheat, items)
    r = Report(cheat)
    rts = (_StaticRT(_B1, game.process), _StaticRT(_B2, game.process))
    ops_all = [str(s.get("op", "")).lower() for s in cheat.steps if isinstance(s, dict)]
    caved = cave is not None and ("hook" in ops_all or "alloc" in ops_all)
    cave_lines = _static_caves(rts, cheat, cave, r) if caved else []
    if cheat.params:
        # with a static cave, inputs used only by the cave code / buffers are fixed at their defaults
        other = [s for s in cheat.steps if isinstance(s, dict) and str(s.get("op", "")).lower() not in ("hook", "alloc")]
        if not caved or any(re.search(r"\$" + re.escape(str(p.get("name"))) + r"\b", json.dumps(other + list(cheat.off)))
                            for p in cheat.params if isinstance(p, dict)):
            r.errors.append("has parameters (inputs) - .shn/.mc4/.json cheats cannot ask for a value")
    once = cheat.mode == "once"
    if once and fmt not in ("json",):
        r.errors.append("is a run-once cheat - .shn/.mc4/.ShnExt only have on/off cheats (GoldHEN .json has buttons)")

    def walk(steps: list, off_side: bool) -> list:
        out = []
        for i, s in enumerate(steps):
            if not isinstance(s, dict):
                r.errors.append(f"step {i + 1} is not a step")
                continue
            op = str(s.get("op", "")).lower()
            if op in _IGNORED_OPS:
                continue
            if op in _DROPPED_OPS:
                r.warnings.append(f"the '{op}' step is left out (these formats cannot check bytes first)")
                continue
            if caved and op in ("hook", "alloc") and not off_side:
                continue                                  # done by _static_caves
            if op in ("hook", "alloc") and not off_side and cave is None:
                r.errors.append(f"step {i + 1} {'installs a hook' if op == 'hook' else 'allocates a buffer'} - "
                                "give a code cave location (free space in the game executable) to export it")
                continue
            if op not in ("write", "patch", "asmpatch") or (off_side and op == "asmpatch"):
                why = {"alloc": "allocates memory (a code cave made at run time)",
                       "code": "writes code into a run-time buffer", "hook": "installs a hook",
                       "aob": "searches for bytes (AOB) at run time", "call": "calls a game function",
                       "python": "runs Python", "read": "reads memory", "set": "uses variables",
                       "repeat": "repeats steps", "free": "frees memory", "protect": "changes page protection"}
                r.errors.append(f"step {i + 1} {why.get(op, f'uses {op!r}')} - not possible in these formats")
                continue
            try:
                sec, off = _addr(rts, s["addr"])
                data = _value(rts, s)
            except _NotStatic as exc:
                r.errors.append(f"step {i + 1} ({_desc(s)}) {exc}")
                continue
            except KeyError as exc:
                r.errors.append(f"step {i + 1} is missing {exc}")
                continue
            if sec < 0 and not off_side:
                r.warnings.append(f"{_desc(s)} is an absolute address - written as an Absolute line, it only "
                                  "works if the game always loads at the same place (PS4 games without ASLR)")
            if once and s.get("button_off"):
                try:
                    data = (data, bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", str(s["button_off"]))))
                except ValueError:
                    pass
            out.append((sec, off, data, op, str(s["addr"]), _desc(s)))
        return out

    ons = walk(list(cheat.steps), False)
    hook_sites = {ln.offset for ln in cave_lines if ln.what.startswith("hook ")}
    offs = walk(list(cheat.off), True)
    if not cheat.steps:
        r.errors.append("has no steps")
    if fmt == "shnext":
        for sec, off, *_rest, what in ons + offs:
            if sec != 0:
                r.errors.append(f"{what}: " + ("an absolute address" if sec < 0 else f"section {sec}") +
                                " - ShnExt lines are offsets from the start of the executable only")
                break
            if off >= 1 << 53:      # a JSON number: negative / huge offsets do not survive (read as double)
                r.errors.append(f"{what}: offset 0x{off:X} is before the executable or too large for a "
                                "ShnExt offset")
                break
    used = set()
    for sec, off, data, op, expr, what in ons:
        data, button_off = data if isinstance(data, tuple) else (data, None)
        line = Line(max(sec, 0), off, data, None, expr, what, absolute=sec < 0)
        if once:
            line.off = button_off or data                # GoldHEN buttons: the file's off, else the on value
        else:
            for j, (s2, o2, d2, _op2, _e2, _w2) in enumerate(offs):
                if j not in used and (s2, o2) == (sec, off):
                    if len(d2) != len(data):         # common in GoldHEN files and accepted there
                        r.warnings.append(f"{what}: the off step writes {len(d2)} bytes but the on step writes "
                                        f"{len(data)} - kept as written (GoldHEN accepts it)")
                    line.off = d2
                    used.add(j)
                    break
        r.lines.append(line)
    if cave_lines:
        first = [ln for ln in cave_lines if ln.offset not in hook_sites or not ln.what.startswith("hook ")]
        jumps = [ln for ln in cave_lines if ln.what.startswith("hook ")]
        r.lines = [ln for ln in first if not ln.what.startswith("hook ")] + r.lines + jumps
    if not once:
        for j, (s2, o2, _d2, _op2, _e2, what) in enumerate(offs):
            if j not in used:
                r.errors.append(f"off step '{what}' has no matching on step at the same address "
                                "(each line needs both values)")
    return r


def check_game(game, fmt: str) -> tuple[list, list]:
    """-> (errors, warnings) about the game header.  The same standard for every format (game_ids):
    cheat menus find files by <TITLEID>_<VERSION>."""
    import game_ids  # noqa: PLC0415
    errors, warnings = [], []
    tid = (game.title_id or "").strip().upper()
    ver = (game.version or "").strip()
    if not game_ids.TITLE_ID_FULL.fullmatch(tid):
        errors.append(f"title id {tid or '(empty)'!r} must be CUSA##### or PPSA##### (cheat menus find the file by it)"
                      " - press 'From console' with the game running")
    if not re.fullmatch(r"\d{2}\.\d{2,3}(\.\d{3})?", ver):
        errors.append(f"version {ver or '(empty)'!r} must be the game's app version, e.g. 01.05 (PS4) "
                      "or 01.000.000 (PS5)")
    elif not game_ids.version_ok(ver, tid):
        warnings.append(f"{'PS4' if tid.startswith('CUSA') else 'PS5'} cheat files use versions like "
                        f"{'01.05' if tid.startswith('CUSA') else '01.000.000'} - {ver!r} may not be found by the cheat menu")
    if not (game.name or "").strip():
        errors.append("the game needs a name")
    if not (game.process or "").strip():
        warnings.append("no process name - eboot.bin is used")
    if not (game.author or "").strip():
        warnings.append("no author - the file's Moder / credits field will be empty")
    return errors, warnings


def fill_originals(reports: list, read: Callable[[str, int], bytes]) -> list:
    """Read the original bytes for lines without an off value.  `read(addr_expr, n)` reads the
    running game.  Returns error strings (also added to each report)."""
    errs = []
    for r in reports:
        for ln in r.missing_off():
            try:
                b = read(ln.addr, len(ln.on))
            except Exception as exc:
                msg = f"{ln.what}: could not read the original bytes ({exc})"
                r.errors.append(msg)
                errs.append(f"{r.cheat.name}: {msg}")
                continue
            if len(b) != len(ln.on):
                r.errors.append(f"{ln.what}: read {len(b)} bytes instead of {len(ln.on)}")
                continue
            if b == ln.on:
                r.warnings.append(f"{ln.what}: the game already has the 'on' bytes - is the cheat turned on? "
                                  "Off would then do nothing")
            ln.off = b
    return errs


# ------------------------------------------------------------------ writers
def _qattr(v: str) -> str:
    """Always "..." with &quot; inside, like PS4 Trainer / GoldHEN files (onionHEN looks for Text=")."""
    return '"' + escape(str(v), {'"': "&quot;"}) + '"'


def _hy(b: bytes) -> str:
    return "-".join(f"{x:02X}" for x in b)


def _absolute_first(reports: list) -> list:
    """onionHEN looks for <Absolute> past the end of a Cheatline, so a normal line followed (anywhere
    later in the file) by an Absolute line is read as absolute too.  Writing every Absolute line
    before the normal ones avoids it; inside a cheat that also writes the cave before the jump."""
    if not any(ln.absolute for r in reports for ln in r.lines):
        return reports
    for r in reports:
        r.lines.sort(key=lambda ln: not ln.absolute)          # stable: keeps the order otherwise
    return sorted(reports, key=lambda r: not any(ln.absolute for ln in r.lines))


def build_shn(game, reports: list, declared: str = "utf-8") -> str:
    reports = _absolute_first(reports)
    nl = "\r\n"
    tid = game.title_id.strip().upper()
    out = [f'<?xml version="1.0" encoding="{declared}"?>',
           '<Trainer xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
           f" Game={_qattr(game.name)} Moder={_qattr(game.author or '')} Cusa={_qattr(tid)}"
           f" Version={_qattr(game.version.strip())} Process={_qattr(game.process or 'eboot.bin')}>",
           "  <Items />"]
    for r in reports:
        out.append(f"  <Cheat Text={_qattr(r.cheat.name)}>")
        for ln in r.lines:
            out += ["    <Cheatline>"]
            if ln.absolute:
                out.append("      <Absolute>True</Absolute>")
            out += [
                    f"      <Offset>{ln.offset:X}</Offset>",
                    f"      <Section>{ln.section}</Section>",
                    f"      <ValueOn>{_hy(ln.on)}</ValueOn>",
                    f"      <ValueOff>{_hy(ln.off)}</ValueOff>",
                    "    </Cheatline>"]
        out.append("  </Cheat>")
    out.append("</Trainer>")
    return nl.join(out)


def build_mc4(game, reports: list) -> bytes:
    text = build_shn(game, reports, declared="utf-16").encode("utf-8")   # what existing mc4 files contain
    pad = 16 - len(text) % 16
    return base64.b64encode(cbc_encrypt(MC4_KEY, MC4_IV, text + bytes([pad]) * pad))


def build_json(game, reports: list) -> str:
    mods = []
    for r in reports:
        mods.append({
            "name": r.cheat.name,
            "hint": (r.cheat.description or None),
            "type": "button" if r.cheat.mode == "once" else "checkbox",
            "memory": [{"offset": f"{ln.offset:X}", "on": ln.on.hex().upper(), "off": ln.off.hex().upper(),
                        **({"section": str(ln.section)} if ln.section else {}),
                        **({"absolute": True} if ln.absolute else {})}
                       for ln in r.lines],
        })
    d = {"name": game.name, "id": game.title_id.strip().upper(), "version": game.version.strip(),
         "process": game.process or "eboot.bin", "mods": mods,
         "credits": [a.strip() for a in (game.author or "").split(",") if a.strip()]}
    return json.dumps(d, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------ ShnExt
def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def asm_text(code: bytes, nop_ok: bool = True) -> str:
    """Bytes -> ShnExt assembly text that assembles back to exactly these bytes wherever it is
    assembled: "nop:N" for all-0x90, real instructions when they re-encode identically at two
    different addresses, `.byte` for everything else (relative jumps/calls, odd encodings, data)."""
    if not code:
        raise ValueError("no bytes")
    if nop_ok and code == b"\x90" * len(code):
        return f"nop:{len(code)}"
    import asmgen
    import disasm
    lines, pos = [], 0
    insns = disasm.decode(code, 0, len(code)) if disasm.have_capstone() else []
    for ins in insns:
        if ins.addr != pos:
            break
        raw = bytes(code[pos:pos + ins.size])
        text = ins.text
        try:
            ok = (asmgen.assemble(text, 0) == raw and asmgen.assemble(text, 0x7_0000_0000) == raw)
        except Exception:
            ok = False
        lines.append(text if ok else ".byte " + ", ".join(f"0x{b:02X}" for b in raw))
        pos += ins.size
    if pos < len(code):
        lines.append(".byte " + ", ".join(f"0x{b:02X}" for b in code[pos:]))
    out = "\r\n".join(lines)
    if asmgen.assemble(out, 0) != bytes(code):           # never write something that changes the bytes
        out = ".byte " + ", ".join(f"0x{b:02X}" for b in code)
    return out


SHNEXT_MAX_LINE = 1024          # onionHEN's limit per line (ONION_MAX_PATCH_BYTES); longer lines are split


def _split_line(on: bytes, off: bytes) -> list[tuple[int, bytes, bytes]]:
    """[(relative offset, on, off)] pieces of at most SHNEXT_MAX_LINE bytes, cut at instruction
    boundaries of the 'on' code where possible.  Written one after the other = the same bytes."""
    n = max(len(on), len(off))
    if n <= SHNEXT_MAX_LINE:
        return [(0, on, off)]
    cuts = []
    try:
        import disasm
        cuts = [i.addr for i in disasm.decode(on, 0, len(on))] if disasm.have_capstone() else []
    except Exception:
        cuts = []
    out, pos = [], 0
    while pos < n:
        end = min(n, pos + SHNEXT_MAX_LINE)
        if end < n:
            best = max((c for c in cuts if pos < c <= end), default=end)
            end = best if best > pos else end
        out.append((pos, on[pos:end], off[pos:end]))
        pos = end
    return out


def build_shnext(game, reports: list, items: Optional[dict] = None) -> bytes:
    import shnext_model
    m, why = shnext_module()
    if m is None:
        raise ValueError(why)
    authors = [a.strip() for a in (game.author or "").split(",") if a.strip()]
    entries = []
    for i, r in enumerate(reports):
        known = {(ln.addr, len(ln.on)): ln.off for ln in r.lines}
        patch, errs = shnext_model.cheat_to_reap(r.cheat, i, authors[0] if authors else "", items,
                                                 lambda e, n: known.get((e, n)), game.process or "eboot.bin")
        if patch is None:
            raise ValueError(f"{r.cheat.name}: " + "; ".join(errs))
        js = json.dumps(patch, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        entries.append(base64.b64encode(m.encrypt_entry(i, _raw_deflate(js))).decode("ascii"))
    outer = {"Modder": authors, "patchEntries": entries, "dictionarys": [], "label": None,
             "Comment": "", "ProcessName": m.encrypt_process_name(game.process or "eboot.bin"),
             "Game": game.name, "Cusa": game.title_id.strip().upper(), "Version": game.version.strip(),
             "Cover": None}
    return _raw_deflate(json.dumps(outer, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def build(fmt: str, game, reports: list, items: Optional[dict] = None) -> bytes:
    if fmt == "shn":
        return build_shn(game, reports).encode("utf-8")
    if fmt == "mc4":
        return build_mc4(game, reports)
    if fmt == "json":
        return build_json(game, reports).encode("utf-8")
    if fmt == "shnext":
        return build_shnext(game, reports, items)
    raise ValueError(fmt)


def default_name(game, fmt: str) -> str:
    tid = (game.title_id or "GAME").strip().upper()
    ver = (game.version or "00.00").strip()
    return f"{tid}_{ver}{FORMATS[fmt][1]}"
