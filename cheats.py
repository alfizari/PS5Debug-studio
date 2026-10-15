"""ps5cheat/1 - cheat file format + script engine for ps5debug-NG.

A cheat file is JSON: one game, many cheats, each cheat a list of steps.
Addresses/values are *expressions*:

    0x1234  | 1234 | -5            numbers
    @buf0                          address of a remote buffer
    $name                          script variable (set by read/call/set)
    rax                            last call result
    module(eboot.bin)              base address of a module (ASLR-safe)
    module(main)                   lowest executable mapping
    [ expr ]                       dereference u64 (pointer chain)
    + - *                          arithmetic

    e.g.  [[module(eboot.bin)+0x4A1C00]+0x20]+0x1C4

A step can also be Python:  {"op": "python", "code": "..."}  with the `ps5` API (script_api.py).
"""

from __future__ import annotations

import json
import re
import struct
import time
from dataclasses import dataclass, field

import asmgen
import codecave
from pathlib import Path
from typing import Any, Callable, Optional

FORMAT = "ps5cheat/1"
# Python steps run arbitrary code on this PC.  Apps that run other people's cheats (the Cheat Player)
# switch this off.
PYTHON_STEPS_ALLOWED = True
M64 = (1 << 64) - 1

INT_TYPES = {
    "u8": ("<B", 1), "i8": ("<b", 1),
    "u16": ("<H", 2), "i16": ("<h", 2),
    "u32": ("<I", 4), "i32": ("<i", 4),
    "u64": ("<Q", 8), "i64": ("<q", 8),
    "ptr": ("<Q", 8),
}
FLOAT_TYPES = {"f32": ("<f", 4), "f64": ("<d", 8)}
PROT_BITS = {"r": 1, "w": 2, "x": 4}


TEXT_TYPES = ("utf8", "utf-8", "string", "utf16", "utf16le", "utf-16le")
STRING_PTYPES = ("string", "text")
# {playername} inside utf8/utf16 text -> replaced by the cheat input of that name
_PLACEHOLDER = re.compile(r"\{([A-Za-z_]\w*)\}")


class CheatError(Exception):
    pass


class TitleMismatch(CheatError):
    """The process is another game than the cheat file is for."""

    def __init__(self, pid: int, actual: str, expected: str) -> None:
        super().__init__(f"pid {pid} is title '{actual}', cheat is for {expected} "
                         "(untick 'verify title id' to override)")
        self.pid, self.actual, self.expected = pid, actual, expected


def has_python(steps: list) -> bool:
    """Does any step (also inside repeat) run Python?"""
    for st in steps or []:
        if isinstance(st, dict):
            if str(st.get("op", "")).lower() == "python":
                return True
            if has_python(st.get("steps", [])):
                return True
    return False


def find_placeholders(steps: list) -> list[str]:
    """Names used as {name} inside text values (alloc init / write / patch)."""
    names: list[str] = []

    def walk(lst: list) -> None:
        for s in lst:
            if not isinstance(s, dict):
                continue
            op = str(s.get("op", "")).lower()
            if op == "repeat":
                walk(s.get("steps", []))
                continue
            if op == "alloc" and isinstance(s.get("init"), dict):
                c = s["init"]
            elif op in ("write", "patch"):
                c = s
            else:
                continue
            if str(c.get("type", "")).lower() in TEXT_TYPES:
                for n in _PLACEHOLDER.findall(str(c.get("value", ""))):
                    if n not in names:
                        names.append(n)

    walk(steps)
    return names


def ensure_string_params(steps: list, params: list, off: Optional[list] = None) -> list:
    """Adds a 'string' param for every {name} placeholder that has no param yet."""
    have = {p.get("name") for p in params if isinstance(p, dict)}
    for n in find_placeholders(list(steps) + list(off or [])):
        if n not in have:
            params.append({"name": n, "label": n.replace("_", " ").title(),
                           "type": "string", "default": ""})
            have.add(n)
    return params


def parse_param(ptype: str, text: Any, lookup: Optional[Callable[[str], Optional[int]]] = None):
    """User text -> int/float (or str for 'string' params). `lookup` maps an item name to its id."""
    if ptype.lower() in STRING_PTYPES:
        t = str(text)
        if not t.strip():
            raise CheatError("type a value (empty)")
        return t
    t = str(text).strip()
    if not t:
        raise CheatError("empty value")
    if lookup is not None:
        v = lookup(t)
        if v is not None:
            return float(v) if ptype.lower() in FLOAT_TYPES else int(v)
    if ptype.lower() in FLOAT_TYPES:
        try:
            return float(t)
        except ValueError:
            raise CheatError(f"'{t}' is not a number") from None
    try:
        return int(t, 0)
    except ValueError:
        raise CheatError(f"'{t}' is not a number or a known item") from None


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------
@dataclass
class Cheat:
    name: str
    description: str = ""
    mode: str = "toggle"            # "toggle" (on/off) or "once"
    steps: list = field(default_factory=list)
    off: list = field(default_factory=list)   # extra steps run when disabling
    author: str = ""
    params: list = field(default_factory=list)  # user inputs -> $name in steps

    @staticmethod
    def from_dict(d: dict) -> "Cheat":
        if not isinstance(d, dict) or not d.get("name"):
            raise CheatError("cheat needs a 'name'")
        mode = str(d.get("mode", "toggle")).lower()
        if mode not in ("toggle", "once"):
            raise CheatError("mode must be 'toggle' or 'once'")
        steps = d.get("steps", [])
        off = d.get("off", [])
        if not isinstance(steps, list) or not isinstance(off, list):
            raise CheatError("'steps' and 'off' must be lists")
        params = d.get("params", [])
        if not isinstance(params, list):
            raise CheatError("'params' must be a list")
        seen = set()
        for p in params:
            if not isinstance(p, dict) or not re.fullmatch(r"[A-Za-z_]\w*", str(p.get("name", ""))):
                raise CheatError("each param needs a 'name' (letters/digits/_)")
            if p["name"] in seen:
                raise CheatError(f"duplicate param '{p['name']}'")
            seen.add(p["name"])
            if str(p.get("type", "u32")).lower() not in {**INT_TYPES, **FLOAT_TYPES, **dict.fromkeys(STRING_PTYPES)}:
                raise CheatError(f"param '{p['name']}': bad type '{p.get('type')}'")
        params = ensure_string_params(steps, list(params), off)
        return Cheat(str(d["name"]), str(d.get("description", "")), mode,
                     steps, off, str(d.get("author", "")), params)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"name": self.name}
        if self.description:
            d["description"] = self.description
        d["mode"] = self.mode
        if self.params:
            d["params"] = self.params
        if self.author:
            d["author"] = self.author
        d["steps"] = self.steps
        if self.off:
            d["off"] = self.off
        return d


@dataclass
class Game:
    name: str
    title_id: str = ""
    version: str = ""
    process: str = ""               # optional process name hint
    author: str = ""
    notes: str = ""
    cheats: list[Cheat] = field(default_factory=list)
    path: Optional[Path] = None
    source: str = ""                # file the cheats were imported from (keeps imports apart)

    @staticmethod
    def from_dict(d: dict, path: Optional[Path] = None) -> "Game":
        if not isinstance(d, dict) or not d.get("game"):
            raise CheatError("file needs a 'game' name")
        g = Game(
            name=str(d["game"]),
            title_id=str(d.get("title_id", "")).upper(),
            version=str(d.get("version", "")),
            process=str(d.get("process", "")),
            author=str(d.get("author", "")),
            notes=str(d.get("notes", "")),
            path=path,
            source=str(d.get("source", "")),
        )
        for c in d.get("cheats", []):
            g.cheats.append(Cheat.from_dict(c))
        return g

    def meta_dict(self) -> dict:
        d = {
            "game": self.name, "title_id": self.title_id, "version": self.version,
            "process": self.process, "author": self.author, "notes": self.notes,
        }
        if self.source:
            d["source"] = self.source
        return d

    def to_dict(self) -> dict:
        d = {"format": FORMAT}
        d.update(self.meta_dict())
        d["cheats"] = [c.to_dict() for c in self.cheats]
        return d

    def save(self) -> None:
        if self.path is None:
            raise CheatError("game has no file path")
        self.path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


def load_games(folder: Path) -> tuple[list[Game], list[str]]:
    games: list[Game] = []
    errors: list[str] = []
    folder.mkdir(parents=True, exist_ok=True)
    for p in sorted(folder.glob("*.json")):
        try:
            games.append(Game.from_dict(json.loads(p.read_text(encoding="utf-8")), p))
        except Exception as exc:
            errors.append(f"{p.name}: {exc}")
    return games, errors


# --------------------------------------------------------------------------
# expression parser
# --------------------------------------------------------------------------
_TOK = re.compile(
    r"\s*(module\([^)]*\)|0[xX][0-9a-fA-F]+|\d+|@[\w.\-]+|\$[\w.]+|rax|[\[\]+\-*])"
)


class _Parser:
    def __init__(self, rt: "Runtime", text: str) -> None:
        self.rt = rt
        self.text = text
        s = text.strip()
        self.toks: list[str] = []
        pos = 0
        while pos < len(s):
            m = _TOK.match(s, pos)
            if not m:
                raise CheatError(f"bad expression {text!r} near {s[pos:pos + 10]!r}")
            self.toks.append(m.group(1))
            pos = m.end()
        if not self.toks:
            raise CheatError("empty expression")
        self.i = 0

    def peek(self) -> Optional[str]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        t = self.peek()
        if t is None:
            raise CheatError(f"unexpected end of expression {self.text!r}")
        self.i += 1
        return t

    def parse(self) -> int:
        v = self.expr()
        if self.peek() is not None:
            raise CheatError(f"unexpected {self.peek()!r} in {self.text!r}")
        return v & M64

    def expr(self) -> int:
        v = self.term()
        while self.peek() in ("+", "-"):
            op = self.take()
            r = self.term()
            v = (v + r) if op == "+" else (v - r)
            v &= M64
        return v

    def term(self) -> int:
        v = self.atom()
        while self.peek() == "*":
            self.take()
            v = (v * self.atom()) & M64
        return v

    def atom(self) -> int:
        t = self.take()
        if t == "-":
            return (-self.atom()) & M64
        if t == "[":
            inner = self.expr()
            if self.take() != "]":
                raise CheatError(f"missing ']' in {self.text!r}")
            return self.rt.read_u64(inner)
        if t.startswith("module("):
            return self.rt.module_base(t[7:-1].strip())
        if t.startswith("@"):
            return self.rt.buffer(t[1:]).address
        if t.startswith("$"):
            name = t[1:]
            if name not in self.rt.vars:
                if name in self.rt.strs:
                    raise CheatError(f"${name} is text - use {{{name}}} inside a utf8/utf16 value")
                raise CheatError(f"unknown variable ${name}")
            return self.rt.vars[name] & M64
        if t == "rax":
            return self.rt.state.last_rax & M64
        if t.lower().startswith("0x"):
            return int(t, 16)
        if t.isdigit():
            return int(t)
        raise CheatError(f"unexpected token {t!r}")


# --------------------------------------------------------------------------
# runtime
# --------------------------------------------------------------------------
class Runtime:
    def __init__(self, client, state, pid: int, make_buffer: Callable,
                 log: Callable[[str], None], undo: list) -> None:
        self.client = client
        self.state = state
        self.pid = pid
        self.make_buffer = make_buffer
        self.log = log
        self.undo = undo
        self.vars: dict[str, int] = {}
        self.fparams: dict[str, float] = {}
        self.strs: dict[str, str] = {}      # string params, used as {name} in text
        self.turning_off = False
        self.ftypes: dict[str, str] = {}    # float param -> "f32" / "f64" (its bits go into assembly)
        self._maps = None

    # -- helpers ---------------------------------------------------------
    def ev(self, value: Any) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value & M64
        return _Parser(self, str(value)).parse()

    def asm_ev(self, expr: str) -> int:
        """Like ev(), for names inside assembly: a float input ($speed with type f32/f64) becomes its
        IEEE bits, so `mov eax, $speed` loads the float.  Everything else is the same as ev()."""
        m = re.fullmatch(r"\s*\$([A-Za-z_]\w*)\s*", str(expr))
        if m and m.group(1) in self.fparams:
            v = self.fparams[m.group(1)]
            if self.ftypes.get(m.group(1), "f32") == "f64":
                return struct.unpack("<Q", struct.pack("<d", v))[0]
            return struct.unpack("<I", struct.pack("<f", v))[0]
        return self.ev(expr)

    def template(self, text: str) -> str:
        """Replace {name} with the string param of that name (others left as-is)."""
        return _PLACEHOLDER.sub(lambda m: self.strs.get(m.group(1), m.group(0)), text)

    def read_u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.client.read(self.pid, addr, 8))[0]

    def buffer(self, name: str):
        for b in self.state.buffers:
            if b.name == name:
                return b
        raise CheatError(f"buffer @{name} is used but no step creates it - in the Cheat Editor press "
                         f"'Check & fix' (it adds the missing alloc step), or add an alloc step named '{name}'")

    def module_base(self, name: str) -> int:
        if self._maps is None:
            self._maps = self.client.maps(self.pid)
        maps = self._maps
        section = None
        if "#" in name:                      # module(main#1) = 2nd mapping (section) of that module
            name, _, sec = name.partition("#")
            section = int(sec.strip() or "0", 0)
        if name.lower() in ("", "main") and section is not None:
            exe = [m for m in maps if m.prot & 4]
            if not exe:
                raise CheatError("no executable mapping in the process")
            name = min(exe, key=lambda m: m.start).name
        if section is not None:
            secs = sorted((m for m in maps if m.name == name), key=lambda m: m.start)
            if section >= len(secs):
                raise CheatError(f"module '{name}' has {len(secs)} section(s), #{section} does not exist")
            return secs[section].start
        if name.lower() in ("", "main"):
            cands = [m for m in maps if m.prot & 4]
        else:
            low = name.lower()
            cands = [m for m in maps if m.name.lower() == low]
            if not cands:
                cands = [m for m in maps if low in m.name.lower()]
        if not cands:
            raise CheatError(f"module '{name}' not found in process maps")
        return min(m.start for m in cands)

    def fnum(self, v: Any) -> float:
        """Float value, allowing $param references."""
        if isinstance(v, str) and v.strip().startswith("$"):
            n = v.strip()[1:]
            if n in self.fparams:
                return self.fparams[n]
            if n in self.vars:
                return float(self.vars[n])
            raise CheatError(f"unknown variable ${n}")
        return float(v)

    def encode(self, typ: str, value: Any, nul: bool = False) -> bytes:
        t = str(typ).lower()
        if t in INT_TYPES:
            size = INT_TYPES[t][1]
            return (self.ev(value) & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        if t in FLOAT_TYPES:
            return struct.pack(FLOAT_TYPES[t][0], self.fnum(value))
        if t in ("utf8", "utf-8", "string"):
            return self.template(str(value)).encode("utf-8") + (b"\0" if nul else b"")
        if t in ("utf16", "utf16le", "utf-16le"):
            return self.template(str(value)).encode("utf-16le") + (b"\0\0" if nul else b"")
        if t in ("hex", "bytes"):
            h = "".join(ch for ch in str(value) if ch not in " \t\r\n,")
            if h[:2].lower() == "0x":
                h = h[2:]
            if len(h) % 2:
                raise CheatError(f"odd number of hex digits in {value!r}")
            return bytes.fromhex(h) + (b"\0" if nul else b"")
        raise CheatError(f"unknown type '{typ}'")

    def arg_bits(self, item: Any) -> int:
        """Call argument: expression, or {"type": "f32"|"f64"|..., "value": ...}."""
        if isinstance(item, dict):
            t = str(item.get("type", "u64")).lower()
            v = item.get("value", 0)
            if t == "f32":
                return struct.unpack("<I", struct.pack("<f", self.fnum(v)))[0]
            if t == "f64":
                return struct.unpack("<Q", struct.pack("<d", self.fnum(v)))[0]
            if t in INT_TYPES:
                return self.ev(v) & ((1 << (8 * INT_TYPES[t][1])) - 1)
            raise CheatError(f"bad arg type '{t}'")
        return self.ev(item)

    def decode(self, typ: str, data: bytes) -> tuple[int, str]:
        t = str(typ).lower()
        if t in INT_TYPES:
            fmt, size = INT_TYPES[t]
            v = struct.unpack(fmt, data[:size])[0]
            return v & M64, (f"0x{v & M64:X} ({v})" if v >= 0 else str(v))
        if t in FLOAT_TYPES:
            fmt, size = FLOAT_TYPES[t]
            v = struct.unpack(fmt, data[:size])[0]
            bits = int.from_bytes(data[:size], "little")
            return bits, str(v)
        raise CheatError(f"cannot read type '{typ}'")

    # -- execution ---------------------------------------------------------
    def run(self, steps: list, depth: int = 0) -> None:
        if depth > 8:
            raise CheatError("repeat nested too deeply")
        for i, step in enumerate(steps):
            try:
                self._step(step, depth)
            except Exception as exc:
                op = step.get("op") if isinstance(step, dict) else step
                msg = str(exc)
                if op in ("alloc", "free", "call", "code", "hook") and msg.endswith("failed: ERROR"):
                    # ps5debug-NG refuses allocation / free / remote calls while the game is stopped at a debugger event
                    msg += " (if the Debugger tab has the game stopped at a breakpoint, press Continue first)"
                raise CheatError(f"step {i + 1} ({op}): {msg}") from exc

    def _step(self, s: dict, depth: int) -> None:
        if not isinstance(s, dict) or "op" not in s:
            raise CheatError("step must be an object with 'op'")
        op = str(s["op"]).lower()
        c, pid, log = self.client, self.pid, self.log

        if op == "alloc":
            name, size = str(s["name"]), self.ev(s["size"])
            old = next((b for b in self.state.buffers if b.name == name), None)
            near = self.ev(s["near"]) if s.get("near") else None
            if old and s.get("reuse", True) and old.size >= size and (
                    near is None or codecave.in_near_range(near, old.address)):
                addr = old.address
                log(f"  reuse @{name} 0x{addr:X}")
            else:
                if old:
                    c.free(pid, old.address, old.size)
                    self.state.buffers.remove(old)
                addr = self._alloc_near(self.ev(s["near"]), size) if s.get("near") else c.alloc(pid, size)
                self.state.buffers.append(self.make_buffer(name, addr, size))
                log(f"  alloc @{name} 0x{addr:X} ({size} bytes)")
            init = s.get("init")
            if init:
                itype = str(init.get("type", "utf8")).lower()
                nul = init.get("nul", itype in ("utf8", "utf-8", "string", "utf16", "utf16le", "utf-16le"))
                data = self.encode(itype, init.get("value", ""), bool(nul))
                if len(data) > size:
                    raise CheatError(f"init is {len(data)} bytes but @{name} is only {size} "
                                     f"(shorten the text or raise 'size')")
                if _PLACEHOLDER.search(str(init.get("value", ""))) and itype in TEXT_TYPES:
                    data = data.ljust(size, b"\0")   # wipe leftovers of a longer earlier text
                c.write(pid, addr, data)
            if "prot" in s:
                c.protect(pid, addr, size, self._prot(s["prot"]))

        elif op == "code":
            name, code = str(s["name"]), str(s["asm"])
            size = self.ev(s["size"]) if "size" in s else None
            align = int(s.get("align", 16))
            auto_ret = bool(s.get("auto_ret", True))
            try:
                resolved = asmgen.substitute(code, self.asm_ev)
                if s.get("auto_frame", True):
                    resolved, frame = asmgen.auto_frame(resolved)
                    if frame:
                        log(f"  (auto stack frame: sub rsp, 0x{frame:X} ... add rsp, 0x{frame:X})")
                if auto_ret and asmgen.needs_ret(resolved):
                    resolved = asmgen.ensure_ret(resolved, True)
                    log("  (no ret/jmp at end - appended 'ret')")
                raw = asmgen.assemble(resolved)          # first pass: learn the size
            except asmgen.AsmError as exc:
                raise CheatError(str(exc)) from exc
            old = next((b for b in self.state.buffers if b.name == name), None)
            need = len(asmgen.pad(raw + b"\x90" * 16, size, align)) if not size else size
            near = self.ev(s["near"]) if s.get("near") else None
            if old and s.get("reuse", True) and old.size >= need and (
                    near is None or codecave.in_near_range(near, old.address)):
                addr = old.address
                log(f"  reuse code @{name} 0x{addr:X}")
            else:
                if old:
                    c.free(pid, old.address, old.size)
                    self.state.buffers.remove(old)
                addr = self._alloc_near(near, need) if near is not None else c.alloc(pid, need)
                self.state.buffers.append(self.make_buffer(name, addr, need))
                log(f"  alloc code @{name} 0x{addr:X}  ({need} bytes)")
            try:
                raw = asmgen.assemble(resolved, addr)    # final: relative jumps/calls are right at this address
            except asmgen.AsmError as exc:
                raise CheatError(str(exc)) from exc
            data = asmgen.pad(raw, size, align)
            cap = next(b.size for b in self.state.buffers if b.name == name)
            if len(data) > cap:
                raise CheatError(f"code @{name} is {len(data)} bytes, its buffer only {cap} - give the step a bigger 'size'")
            c.write(pid, addr, data)
            c.protect(pid, addr, len(data), self._prot(s.get("prot", "rx")))
            log(f"  code bytes: {raw[:32].hex(' ')}{' ...' if len(raw) > 32 else ''}")

        elif op == "hook":
            self._hook(s)

        elif op == "aob":
            self._aob(s)

        elif op == "asmpatch":
            # assemble at the target address (relative jumps right) and write; the
            # original bytes are restored when a toggle cheat is turned off
            addr = self.ev(s["addr"])
            try:
                code = asmgen.substitute(str(s["asm"]), self.asm_ev)
                data = asmgen.assemble(code, addr)
            except asmgen.AsmError as exc:
                raise CheatError(str(exc)) from exc
            self.undo.append((addr, c.read(pid, addr, len(data))))
            c.write(pid, addr, data)
            log(f"  asmpatch 0x{addr:X} <- {data.hex(' ')}")

        elif op == "free":
            b = self.buffer(str(s["name"]))
            c.free(pid, b.address, b.size)
            self.state.buffers.remove(b)
            log(f"  free @{b.name}")

        elif op in ("write", "patch"):
            addr = self._site(s)
            data = self.encode(s["type"], s["value"], bool(s.get("nul", False)))
            if op == "patch":
                self.undo.append((addr, c.read(pid, addr, len(data))))
            c.write(pid, addr, data)
            log(f"  {op} 0x{addr:X} <- {data[:16].hex(' ')}{'...' if len(data) > 16 else ''}")

        elif op == "read":
            addr = self.ev(s["addr"])
            t = str(s.get("type", "u32")).lower()
            size = (INT_TYPES.get(t) or FLOAT_TYPES.get(t) or (None, 0))[1]
            if not size:
                raise CheatError(f"cannot read type '{t}'")
            bits, text = self.decode(t, c.read(pid, addr, size))
            if "store" in s:
                self.vars[str(s["store"])] = bits
            log(f"  read 0x{addr:X} {t} = {text}")

        elif op == "call":
            rip = self.ev(s["rip"])
            args = list(s.get("args", []))
            if len(args) > 6:
                raise CheatError("max 6 args")
            vals = [self.arg_bits(a) for a in args] + [0] * (6 - len(args))
            # "raw": true skips the stack-safe trampoline for this one call
            safe = None if not s.get("raw") else False
            rax = c.call(pid, rip, *vals, rpcstub=self.ev(s.get("rpcstub", 0)), safe=safe)
            self.state.last_rax = rax
            self.vars["ret"] = rax
            if "store" in s:
                self.vars[str(s["store"])] = rax
            log(f"  call 0x{rip:X}({', '.join(f'0x{v:X}' for v in vals[:len(args)])}) -> 0x{rax:X}")

        elif op == "protect":
            addr, size = self.ev(s["addr"]), self.ev(s["size"])
            c.protect(pid, addr, size, self._prot(s["prot"]))
            log(f"  protect 0x{addr:X} +0x{size:X} {s['prot']}")

        elif op == "set":
            self.vars[str(s["var"])] = self.ev(s["value"])

        elif op == "check":
            addr = self.ev(s["addr"])
            t = str(s.get("type", "u32")).lower()
            if t in ("hex", "bytes"):
                want = self.encode("hex", s["value"])
                got = c.read(pid, addr, len(want))
                ok = got == want
                detail = f"got {got.hex(' ')}, want {want.hex(' ')}"
            else:
                size = INT_TYPES[t][1]
                got_v = self.decode(t, c.read(pid, addr, size))[0]
                want_v = self.ev(s["equals"]) & ((1 << (8 * size)) - 1)
                ok = got_v == want_v
                detail = f"got 0x{got_v:X}, want 0x{want_v:X}"
            if not ok:
                raise CheatError(s.get("msg") or f"check failed at 0x{addr:X}: {detail}")
            log(f"  check 0x{addr:X} ok")

        elif op == "log":
            extra = f" = 0x{self.ev(s['value']):X}" if "value" in s else ""
            log(f"  {s.get('text', '')}{extra}")

        elif op == "sleep":
            time.sleep(float(s.get("ms", 100)) / 1000.0)

        elif op == "python":
            # {"op": "python", "code": "ps5.write_u32('@stats', 99)"} - see script_api.py
            if not PYTHON_STEPS_ALLOWED:
                raise CheatError("this cheat contains a Python step, which this app does not run")
            import script_api   # noqa: PLC0415
            try:
                script_api.run_code(str(s.get("code", "")), self, lambda t: log(f"  {t}"),
                                    getattr(self, "stop_event", None), name=str(s.get("name") or "<python step>"))
            except script_api.ScriptError as exc:
                raise CheatError(str(exc)) from exc

        elif op == "repeat":
            for _ in range(int(s.get("count", 1))):
                self.run(s.get("steps", []), depth + 1)
                if s.get("delay_ms"):
                    time.sleep(float(s["delay_ms"]) / 1000.0)
        else:
            raise CheatError(f"unknown op '{op}'")

    # -- AOB signature --------------------------------------------------------
    def _aob(self, s: dict) -> None:
        """{"op":"aob","pattern":"48 8B ?? 05","store":"site","module":"main","offset":0,
            "index":1,"data":false}  ->  $site = address of the match (+offset).
        Searches the module's code (or all its readable memory with "data": true)."""
        import aob as aobmod
        c, pid, log = self.client, self.pid, self.log
        try:
            pat, mask = aobmod.parse(str(s["pattern"]))
        except aobmod.AobError as exc:
            raise CheatError(str(exc)) from exc
        module = str(s.get("module", "main"))
        index = int(s.get("index", 1))
        cache = getattr(self.state, "aob_cache", None)
        if cache is None:
            cache = self.state.aob_cache = {}
        key = (self.pid, pat, mask, module, index, bool(s.get("data")))
        addr = cache.get(key, 0)
        if addr:                                   # still there?  (cheap re-check instead of a rescan)
            cur = c.read(pid, addr, len(pat))
            if any(m and a != b for a, b, m in zip(cur, pat, mask)):
                addr = 0
        if not addr:
            if self._maps is None:
                self._maps = c.maps(pid)
            try:
                ranges = aobmod.regions(self._maps, module, code_only=not s.get("data"))
            except aobmod.AobError as exc:
                raise CheatError(str(exc)) from exc
            addr = aobmod.find(c, pid, ranges, pat, mask, index)
            if not addr:
                raise CheatError(s.get("msg") or f"AOB not found ({aobmod.fmt(pat, mask)}) - "
                                 "different game version, or the code is already patched")
            cache[key] = addr
        addr = (addr + self.ev(s.get("offset", 0))) & M64
        name = str(s.get("store", "aob"))
        self.vars[name] = addr
        log(f"  aob {aobmod.fmt(pat, mask)[:47]} -> ${name} = 0x{addr:X}")

    # -- GoldHEN / PS4 compatibility: where does an imported line really go? -------
    def _site(self, s: dict) -> int:
        """Address of a write/patch step.  Two optional keys (set by the .shn/.mc4/.json importer):

        "alt": "module(main)+0x..."  - a Section N line: the PS4 tools meant "offset into the Nth
            mapping", onionHEN/GoldHEN-style loaders use "offset from the executable base".  The
            one that holds the line's original bytes ("verify": {"off": hex, "on": hex}) wins.
        "mc": {"addr": EXPR, "size": N, "offset": raw}  - a Master Code dependent ("... MC" cheat):
            its bytes are found inside the code the Master Code wrote (like GoldHEN / onionHEN),
            else the low byte of its offset is kept inside the master's 256-byte block.
        The choice is remembered per game process, so turning the cheat off uses the same address."""
        if "alt" not in s and "mc" not in s:
            return self.ev(s["addr"])
        picks = getattr(self.state, "site_picks", None)
        if picks is None:
            picks = self.state.site_picks = {}
        key = (self.pid, str(s["addr"]))
        if key in picks and (self.turning_off or picks[key][1]):
            return picks[key][0]                 # off: same place as on; on: only re-use a verified pick
        ver = s.get("verify") or {}
        wants = [self.encode("hex", ver[k]) for k in ("off", "on") if str(ver.get(k) or "").strip()]
        c, pid = self.client, self.pid
        if "mc" in s:
            mc = s["mc"]
            maddr, size = self.ev(mc["addr"]), int(mc.get("size", 0))
            buf = c.read(pid, maddr, size) if size > 0 else b""
            hit = next((buf.find(w) for w in wants if w and buf.find(w) >= 0), -1)
            if hit >= 0:
                addr, how, done = maddr + hit, "found in the Master Code", True
            else:
                addr, how, done = ((maddr & ~0xFF) | (int(mc.get("offset", 0)) & 0xFF),
                                   "Master Code block - not verified, is the Master Code on?", False)
        else:
            cands = []
            for expr in (s["addr"], s["alt"]):
                try:
                    cands.append((self.ev(expr), str(expr)))
                except CheatError:
                    pass                          # e.g. the module has no section N
            if not cands:
                raise CheatError(f"neither {s['addr']} nor {s['alt']} can be resolved")
            addr, how = cands[0][0], f"{cands[0][1]} (not verified)"
            done = False
            for w in wants:
                for a, expr in cands:
                    if w and c.read(pid, a, len(w)) == w:
                        addr, how, done = a, expr, True
                        break
                if done:
                    break
        picks[key] = (addr, done)
        self.log(f"  {s['addr']} -> 0x{addr:X} ({how})")
        return addr

    # -- code cave hook ------------------------------------------------------
    def _alloc_near(self, site: int, size: int) -> int:
        """Executable memory within +-2 GB of `site` (needed for a 5-byte jump)."""
        c, pid = self.client, self.pid
        for delta in (-0x4000000, 0x4000000, -0x10000000, 0x10000000, -0x40000000, 0x40000000):
            hint = (site + delta) & ~0x3FFF
            if hint <= 0:
                continue
            try:
                addr = c.alloc_hinted(pid, hint, size)
            except Exception:
                continue
            if codecave.in_near_range(site, addr):
                return addr
            try:
                c.free(pid, addr, size)
            except Exception:
                pass
        raise CheatError("no free memory within 2 GB of the hook address - tick 'far jump' "
                         "(needs 14 stolen bytes) or use a different hook address")

    def _hook(self, s: dict) -> None:
        """{"op":"hook","name":"h","addr":EXPR,"orig":"8B 45 F8 ...","asm":"...","far":false}
        Replaces the instruction(s) at addr (whose bytes are `orig`) by a jump
        to a cave running `asm`, then returning after them. Undone like `patch`."""
        c, pid, log = self.client, self.pid, self.log
        name = str(s.get("name") or "hook")
        addr = self.ev(s["addr"])
        if str(s.get("orig", "")).lower() == "auto":
            orig = c.read(pid, addr, int(s.get("length", 5)))
        else:
            orig = self.encode("hex", s["orig"])
        far = bool(s.get("far", False))
        asm = str(s.get("asm", ""))
        jl = codecave.jump_len(far)
        if len(orig) < jl:
            raise CheatError(f"hook {name}: 'orig' is {len(orig)} bytes, a {'far' if far else 'near'} jump needs {jl}")
        resume = addr + len(orig)

        # re-apply while already hooked: put the original bytes back first
        prior = next((o for a, o in self.undo if a == addr), None)
        if prior is not None:
            c.write(pid, addr, prior)
        cur = c.read(pid, addr, len(orig))
        if cur != orig:
            raise CheatError(
                f"hook {name}: bytes at 0x{addr:X} are [{cur.hex(' ')}] but the cheat expects [{orig.hex(' ')}] "
                "(different game version, a breakpoint, or another patch is there)")

        try:
            probe = codecave.assemble_cave(asm, addr, self.asm_ev, resume)   # only to learn the size
        except asmgen.AsmError as exc:
            raise CheatError(str(exc)) from exc
        size = ((len(probe) + 0x20) + 15) & ~15

        old = next((b for b in self.state.buffers if b.name == name), None)
        if old and s.get("reuse", True) and old.size >= size and (far or codecave.in_near_range(addr, old.address)):
            cave = old.address
            log(f"  reuse cave @{name} 0x{cave:X}")
        else:
            if old:
                c.free(pid, old.address, old.size)
                self.state.buffers.remove(old)
            cave = c.alloc(pid, size) if far else self._alloc_near(addr, size)
            self.state.buffers.append(self.make_buffer(name, cave, size))
            log(f"  alloc cave @{name} 0x{cave:X} ({size} bytes)")
            old = None
        size = old.size if old else size

        try:
            code = codecave.assemble_cave(asm, cave, self.asm_ev, resume)
        except asmgen.AsmError as exc:
            raise CheatError(str(exc)) from exc
        if len(code) > size:
            raise CheatError(f"hook {name}: cave code is {len(code)} bytes but the cave is {size}; run again")
        code = code.ljust(size, b"\xCC")
        c.write(pid, cave, code)
        c.protect(pid, cave, size, self._prot(s.get("prot", "rx")))

        patch = codecave.hook_bytes(addr, cave, len(orig), far)
        if prior is None:
            self.undo.append((addr, orig))
        c.write(pid, addr, patch)
        log(f"  hook 0x{addr:X} -> cave 0x{cave:X}  ({len(orig)} byte(s) replaced, resumes at 0x{resume:X})")

    @staticmethod
    def _prot(p: Any) -> int:
        if isinstance(p, int):
            return p
        bits = 0
        for ch in str(p).lower():
            if ch not in PROT_BITS:
                raise CheatError(f"bad prot '{p}' (use letters r/w/x)")
            bits |= PROT_BITS[ch]
        return bits


def execute(cheat: Cheat, game: Game, client, state, pid: int, make_buffer: Callable,
            log: Callable[[str], None], undo: list, off: bool = False,
            verify_title: bool = True, params: Optional[dict] = None) -> None:
    """Enable (or disable) a cheat. `undo` holds original bytes of `patch` steps."""
    if verify_title and game.title_id:
        info = client.proc_info(pid)
        if info.titleid.strip().upper() != game.title_id.upper():
            raise TitleMismatch(pid, info.titleid.strip(), game.title_id.upper())
    rt = Runtime(client, state, pid, make_buffer, log, undo)
    rt.ftypes = {str(p.get("name")): str(p.get("type", "")).lower() for p in (cheat.params or [])
                 if isinstance(p, dict) and str(p.get("type", "")).lower() in FLOAT_TYPES}
    for pname, pval in (params or {}).items():
        if isinstance(pval, str):
            rt.strs[pname] = pval
            continue
        if isinstance(pval, float):
            rt.fparams[pname] = pval
        rt.vars[pname] = int(pval) & M64
    rt.turning_off = off
    if off:
        # restore newest first; an entry is dropped only once its write worked, so a failed
        # disable (game busy / connection hiccup) can simply be retried
        while undo:
            addr, orig = undo[-1]
            client.write(pid, addr, orig)
            undo.pop()
            log(f"  restore 0x{addr:X} ({len(orig)} bytes)")
        rt.run(cheat.off)
    else:
        rt.run(cheat.steps)
