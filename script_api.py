"""Python scripting for ps5debug - the `ps5` object scripts use.

Scripts run in the tool (on the PC) and drive the game through the same engine as the
Cheat Editor's JSON steps, so the two mix freely:
  * a buffer made with ps5.alloc("stats") is the @stats that JSON steps use (and back);
  * ps5.patch()/asm_patch()/hook() are undone when a toggle cheat is turned off;
  * $variables set by JSON steps are ps5.var("name"), and ps5.var("name", value) sets them.

A script is saved inside a cheat as a step:   {"op": "python", "code": "..."}

    hp = ps5.pointer(ps5.module() + 0x4A1C00, 0x20, 0x1C4)
    ps5.write_u32(hp, 999)

    site = ps5.aob("48 8B 05 ?? ?? ?? ?? 8B 40 1C")
    buf = ps5.alloc("stats", 64, init=bytes([99]) * 64)
    ps5.call(ps5.module() + 0x123450, buf, 64)
"""

from __future__ import annotations

import math
import struct
import threading
import time
import traceback
from typing import Any, Callable, Iterable, Optional, Union

M64 = (1 << 64) - 1
_FMT = {"u8": "<B", "i8": "<b", "u16": "<H", "i16": "<h", "u32": "<I", "i32": "<i",
        "u64": "<Q", "i64": "<q", "ptr": "<Q", "f32": "<f", "float": "<f", "f64": "<d", "double": "<d"}
Num = Union[int, str]


class ScriptStopped(Exception):
    """Raised inside a script when the user presses Stop (or the cheat is cancelled)."""


class ScriptError(Exception):
    pass


class Buffer(int):
    """A remote buffer: behaves like its address (an int) and also has .name / .size."""

    def __new__(cls, address: int, name: str, size: int):
        obj = int.__new__(cls, address)
        obj.name, obj.size = name, size
        return obj

    def __repr__(self) -> str:
        return f"@{self.name} 0x{int(self):X} ({self.size} bytes)"


def _fmt(t: str) -> str:
    f = _FMT.get(str(t).lower())
    if not f:
        raise ScriptError(f"unknown type '{t}' (use u8 u16 u32 u64 i8 i16 i32 i64 f32 f64)")
    return f


class PS5:
    """Everything a script can do.  Addresses may be ints or cheat expressions such as
    "[module(eboot.bin)+0x4A1C00]+0x20", "@stats" or "$site"."""

    def __init__(self, rt, out: Callable[[str], None] = print, stop: Optional[threading.Event] = None) -> None:
        self._rt = rt
        self._out = out
        self._stop = stop or threading.Event()

    # ------------------------------------------------------------------ basics
    @property
    def pid(self) -> int:
        """The game process id."""
        return self._rt.pid

    @property
    def client(self):
        """The raw ps5debug client (advanced)."""
        return self._rt.client

    @property
    def g(self) -> dict:
        """A dict kept between runs (e.g. remember things when a cheat is turned on, use them when off)."""
        st = self._rt.state
        if not hasattr(st, "script_globals"):
            st.script_globals = {}
        return st.script_globals

    def _check(self) -> None:
        if self._stop.is_set():
            raise ScriptStopped()

    def addr(self, a: Num) -> int:
        """Number or cheat expression -> address."""
        self._check()
        return int(a) & M64 if isinstance(a, int) else self._rt.ev(a)

    expr = addr

    def log(self, *args: Any) -> None:
        """Print to the script output / cheat log.  Address-sized ints (>= 0x10000) are shown in hex."""
        parts = [f"0x{a:X}" if isinstance(a, int) and not isinstance(a, bool) and a >= 0x10000 else str(a)
                 for a in args]
        self._out(" ".join(parts))

    def sleep(self, seconds: float) -> None:
        """Sleep, but wake up immediately when Stop is pressed."""
        if self._stop.wait(max(0.0, float(seconds))):
            raise ScriptStopped()

    def stopped(self) -> bool:
        """True once Stop was pressed - for long loops:  while not ps5.stopped(): ..."""
        return self._stop.is_set()

    def var(self, name: str, value: Optional[int] = None) -> Optional[int]:
        """Get (or set) a $variable shared with JSON steps."""
        name = name.lstrip("$")
        if value is not None:
            self._rt.vars[name] = int(value) & M64
            return self._rt.vars[name]
        if name not in self._rt.vars:
            raise ScriptError(f"${name} is not set")
        return self._rt.vars[name]

    def param(self, name: str, default: Any = None) -> Any:
        """The value of a cheat input ($param) - text inputs come back as str."""
        rt = self._rt
        if name in rt.strs:
            return rt.strs[name]
        if name in rt.fparams:
            return rt.fparams[name]
        return rt.vars.get(name, default)

    # ------------------------------------------------------------------ memory
    def read(self, addr: Num, size: int) -> bytes:
        return self._rt.client.read(self.pid, self.addr(addr), int(size))

    def write(self, addr: Num, data: Union[bytes, bytearray, str]) -> None:
        """Write bytes (or a hex string "90 90") - permanent, not undone."""
        if isinstance(data, str):
            data = bytes.fromhex(data.replace(" ", ""))
        self._rt.client.write(self.pid, self.addr(addr), bytes(data))

    def patch(self, addr: Num, data: Union[bytes, bytearray, str]) -> None:
        """Write and remember the original bytes: restored when the (toggle) cheat is turned off."""
        a = self.addr(addr)
        if isinstance(data, str):
            data = bytes.fromhex(data.replace(" ", ""))
        self._rt.undo.append((a, self._rt.client.read(self.pid, a, len(data))))
        self._rt.client.write(self.pid, a, bytes(data))

    def read_value(self, addr: Num, type: str = "u32") -> Any:
        f = _fmt(type)
        return struct.unpack(f, self.read(addr, struct.calcsize(f)))[0]

    def write_value(self, addr: Num, value: Any, type: str = "u32", undo: bool = False) -> None:
        f = _fmt(type)
        if f[-1] in "fd":
            data = struct.pack(f, float(value))
        else:
            size = struct.calcsize(f)
            data = (int(value) & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        (self.patch if undo else self.write)(addr, data)

    def read_values(self, addr: Num, count: int, type: str = "u32") -> list:
        f = _fmt(type)
        n = struct.calcsize(f)
        return list(struct.unpack("<" + f[1] * int(count), self.read(addr, n * int(count))))

    def read_multi(self, items: Iterable[tuple[Num, int]]) -> list[bytes]:
        """Many (address, size) reads in one round trip."""
        return self._rt.client.read_multi(self.pid, [(self.addr(a), int(n)) for a, n in items])

    def read_string(self, addr: Num, max_len: int = 256, encoding: str = "utf-8") -> str:
        raw = self.read(addr, max_len)
        if encoding.lower().replace("-", "") in ("utf16", "utf16le"):
            end = next((i for i in range(0, len(raw) - 1, 2) if raw[i] == 0 and raw[i + 1] == 0), len(raw))
            return raw[:end].decode("utf-16le", "replace")
        return raw.split(b"\0", 1)[0].decode(encoding, "replace")

    def write_string(self, addr: Num, text: str, encoding: str = "utf-8", nul: bool = True) -> None:
        enc = "utf-16le" if encoding.lower().replace("-", "") in ("utf16", "utf16le") else encoding
        data = text.encode(enc) + ((b"\0\0" if enc == "utf-16le" else b"\0") if nul else b"")
        self.write(addr, data)

    def fill(self, addr: Num, size: int, byte: int = 0) -> None:
        self.write(addr, bytes([byte & 0xFF]) * int(size))

    def pointer(self, base: Num, *offsets: int) -> int:
        """Follow a pointer chain:  pointer(B, o1, o2) = [[B]+o1]+o2  (like Cheat Engine's base -> o1 -> o2)."""
        a = self.addr(base)
        for o in offsets:
            a = (self.read_value(a, "u64") + int(o)) & M64
        return a

    # typed shortcuts: read_u32(addr) / write_u32(addr, value) ...
    def __getattr__(self, name: str):
        for pre in ("read_", "write_"):
            if name.startswith(pre):
                t = name[len(pre):]
                if t in _FMT:
                    if pre == "read_":
                        return lambda addr, _t=t: self.read_value(addr, _t)
                    return lambda addr, value, undo=False, _t=t: self.write_value(addr, value, _t, undo)
        raise AttributeError(f"ps5 has no '{name}' - see the API list in the script window")

    # ------------------------------------------------------------------ buffers / code
    def alloc(self, name: str, size: int = 0x1000, init: Union[bytes, str, None] = None,
              near: Optional[Num] = None, prot: Optional[str] = None) -> Buffer:
        """Allocate (or reuse) the remote buffer @name.  init: bytes, or text (written as UTF-8 + NUL)."""
        step: dict = {"op": "alloc", "name": name, "size": int(size)}
        if near is not None:
            step["near"] = self.addr(near)
        if prot:
            step["prot"] = prot
        self._rt._step(step, 0)
        b = self.buffer(name)
        if init is not None:
            data = init.encode("utf-8") + b"\0" if isinstance(init, str) else bytes(init)
            if len(data) > b.size:
                raise ScriptError(f"init is {len(data)} bytes, @{name} only {b.size}")
            self.write(b, data)
        return b

    def buffer(self, name: str) -> Buffer:
        b = self._rt.buffer(name.lstrip("@"))
        return Buffer(b.address, b.name, b.size)

    def buffers(self) -> dict[str, Buffer]:
        return {b.name: Buffer(b.address, b.name, b.size) for b in self._rt.state.buffers}

    def free(self, name: str) -> None:
        self._rt._step({"op": "free", "name": name.lstrip("@")}, 0)

    def asm(self, code: str, at: Num = 0) -> bytes:
        """Assemble x86-64 (Intel syntax) as if placed at `at`.  @buf / $var / module(..) work inside."""
        import asmgen   # noqa: PLC0415
        return asmgen.assemble(asmgen.substitute(code, self._rt.ev), self.addr(at) if at else 0)

    def code(self, name: str, asm: str, near: Optional[Num] = None) -> Buffer:
        """Assemble `asm` into the executable buffer @name (stack frame / ret added like a 'code' step)."""
        step: dict = {"op": "code", "name": name, "asm": asm}
        if near is not None:
            step["near"] = self.addr(near)
        self._rt._step(step, 0)
        return self.buffer(name)

    def asm_patch(self, addr: Num, code: str) -> bytes:
        """Assemble at addr and write it there (undone when the cheat is turned off)."""
        a = self.addr(addr)
        data = self.asm(code, a)
        self.patch(a, data)
        return data

    def nop(self, addr: Num, size: int) -> None:
        self.patch(addr, b"\x90" * int(size))

    def hook(self, addr: Num, asm: str, name: str = "hook", length: Optional[int] = None,
             far: bool = False) -> None:
        """Code cave: jump from addr to `asm`, then run the replaced instructions' bytes as written in asm.
        Same as a JSON 'hook' step with "orig": "auto"."""
        step = {"op": "hook", "name": name, "addr": self.addr(addr), "orig": "auto", "asm": asm, "far": far}
        if length:
            step["length"] = int(length)
        self._rt._step(step, 0)

    def call(self, func: Num, *args: Any, raw: bool = False, timeout: float = 30.0) -> int:
        """Call a game function with up to 6 integer/pointer arguments (floats: pass ps5.f32(x)); returns rax."""
        if len(args) > 6:
            raise ScriptError("at most 6 arguments")
        vals = []
        for a in args:
            if isinstance(a, float):
                raise ScriptError("float arguments go in xmm registers - use a 'code' buffer for those")
            vals.append(self.addr(a) if not isinstance(a, int) else int(a) & M64)
        vals += [0] * (6 - len(vals))
        rax = self._rt.client.call(self.pid, self.addr(func), *vals, safe=False if raw else None, timeout=timeout)
        self._rt.state.last_rax = rax
        self._rt.vars["ret"] = rax
        return rax

    @staticmethod
    def f32(x: float) -> int:
        """Bits of a float (for memory writes / integer registers)."""
        return struct.unpack("<I", struct.pack("<f", float(x)))[0]

    @staticmethod
    def f64(x: float) -> int:
        return struct.unpack("<Q", struct.pack("<d", float(x)))[0]

    def protect(self, addr: Num, size: int, prot: str = "rwx") -> None:
        self._rt._step({"op": "protect", "addr": self.addr(addr), "size": int(size), "prot": prot}, 0)

    # ------------------------------------------------------------------ modules / search
    def maps(self) -> list:
        return self._rt.client.maps(self.pid)

    def module(self, name: str = "main") -> int:
        """Base address of a module (eboot.bin, libSceX.sprx ...); 'main' = the game executable."""
        return self._rt.module_base(name)

    def aob(self, pattern: str, module: str = "main", data: bool = False, index: int = 1,
            offset: int = 0) -> Optional[int]:
        """Address of the index-th match of an AOB like "48 8B ?? 05" in a module (None if not found)."""
        try:
            self._rt._step({"op": "aob", "pattern": pattern, "module": module, "data": data,
                            "index": index, "offset": offset, "store": "_aob"}, 0)
        except Exception as exc:
            if "not found" in str(exc):
                return None
            raise
        return self._rt.vars["_aob"]

    def aob_all(self, pattern: str, module: str = "main", data: bool = False, limit: int = 32) -> list[int]:
        import aob as aobmod   # noqa: PLC0415
        pat, mask = aobmod.parse(pattern)
        ranges = aobmod.regions(self.maps(), module, code_only=not data)
        return aobmod.find_all(self._rt.client, self.pid, ranges, pat, mask, limit)

    def _ranges(self, start: Optional[Num], length: Optional[int], writable: bool) -> list[tuple[int, int]]:
        if start is not None:
            a = self.addr(start)
            return [(a, int(length or 0x10000))]
        out = []
        for m in self.maps():
            if not (m.prot & 1) or (writable and not (m.prot & 2)) or (m.prot & 4):
                continue
            out.append((m.start, m.end - m.start))
        return out

    def find_bytes(self, data: Union[bytes, str], start: Optional[Num] = None, length: Optional[int] = None,
                   count: int = 100, align: int = 1, writable: bool = True) -> list[int]:
        """Addresses where `data` occurs.  With start/length: that range; otherwise all game data memory."""
        if isinstance(data, str):
            import aob as aobmod   # noqa: PLC0415
            pat, mask = aobmod.parse(data)
            if not all(mask):
                ranges = self._ranges(start, length, writable)
                return aobmod.find_all(self._rt.client, self.pid, ranges, pat, mask, min(count, 255))
            data = pat
        data = bytes(data)
        out: list[int] = []
        chunk = 4 << 20
        for a0, n in self._ranges(start, length, writable):
            a = a0
            end = a0 + n
            while a < end and len(out) < count:
                self._check()
                k = min(chunk + len(data) - 1, end - a)
                try:
                    buf = self._rt.client.read(self.pid, a, k)
                except Exception:
                    a += chunk
                    continue
                i = buf.find(data)
                while i != -1 and len(out) < count:
                    if (a + i) % align == 0:
                        out.append(a + i)
                    i = buf.find(data, i + 1)
                a += chunk
            if len(out) >= count:
                break
        return out

    def find_value(self, value: Any, type: str = "u32", start: Optional[Num] = None,
                   length: Optional[int] = None, count: int = 100, aligned: bool = True) -> list[int]:
        """Addresses holding `value` (u8..u64 / i8..i64 / f32 / f64).
        find_value(99, "u32", start=addr, length=0x1000) searches that range; without start, all game data."""
        f = _fmt(type)
        data = struct.pack(f, float(value) if f[-1] in "fd" else int(value) & ((1 << (8 * struct.calcsize(f))) - 1))
        if start is None:
            hits = self._turbo_find(f, type, data, count, aligned)
            if hits is not None:
                return hits
        return self.find_bytes(data, start, length, count, struct.calcsize(f) if aligned else 1)

    def _turbo_find(self, f: str, type: str, data: bytes, count: int, aligned: bool) -> Optional[list[int]]:
        """Whole-memory exact search on the console (SIMD turbo scan); None if the payload has none."""
        from ps5debug_client import TurboScanSession, VALUE_SIZES   # noqa: PLC0415
        c = self._rt.client
        caps = c.turbo_caps()
        if caps is None:
            return None
        vt = {"u8": 0, "i8": 1, "u16": 2, "i16": 3, "u32": 4, "i32": 5, "u64": 6, "i64": 7, "ptr": 6,
              "f32": 8, "float": 8, "f64": 9, "double": 9}[type.lower()]
        segs = self._ranges(None, None, True)
        sess = TurboScanSession(c, caps)
        try:
            n = sess.first_scan(self.pid, segs, vt, 0, data, None,
                                VALUE_SIZES[vt] if aligned else 1, 0x400 if vt in (8, 9) else 0,
                                keep_first=False)
            res = sess.get(0, min(n, count))
            return [r.addr for r in res]
        finally:
            try:
                sess.end()
            except Exception:
                pass

    # ------------------------------------------------------------------ cheat steps
    def step(self, step: dict) -> None:
        """Run any Cheat Editor JSON step, e.g. ps5.step({"op": "patch", "addr": "@x", "type": "u32", "value": 5})."""
        self._check()
        self._rt._step(step, 0)

    def steps(self, steps: list) -> None:
        self._check()
        self._rt.run(steps)

    # ------------------------------------------------------------------ waiting / loops
    def wait_until(self, cond: Callable[[], bool], timeout: float = 10.0, every: float = 0.1) -> bool:
        """Poll cond() until it is true (returns True) or the timeout passes (returns False)."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cond():
                return True
            self.sleep(every)
        return False

    def every(self, seconds: float, fn: Callable[[], Any], times: Optional[int] = None) -> None:
        """Call fn() every `seconds` until Stop (or `times` times)."""
        k = 0
        while times is None or k < times:
            fn()
            k += 1
            self.sleep(seconds)


API_HELP = """\
MEMORY  (addr = int or cheat expression)
ps5.read(addr, size) -> bytes
ps5.write(addr, b"..." | "90 90")
ps5.patch(addr, data)        undone when the cheat goes Off
ps5.read_u32(addr)           u8 u16 u64 i8 i16 i32 i64 f32 f64 ptr
ps5.write_u32(addr, value, undo=False)
ps5.read_values(addr, count, "u32")
ps5.read_multi([(addr, size), ...])
ps5.read_string(addr, 64, "utf-8")      or "utf-16"
ps5.write_string(addr, "text", "utf-8")
ps5.fill(addr, size, 0)
ps5.pointer(base, 0x20, 0x1C4)          [[base]+0x20]+0x1C4
ps5.addr("[module(eboot.bin)+0x10]+8")  any cheat expression

BUFFERS & CODE
ps5.alloc("name", 0x1000, init=b"", near=None) -> buffer
ps5.buffer("name")      also @name in JSON steps
ps5.buffers()
ps5.free("name")
ps5.asm("mov eax, 1\\nret", at=0) -> bytes
ps5.code("name", "lea rax, [rdi+rsi]\\nret") -> buffer
ps5.asm_patch(addr, "mov eax, 99")       undone on Off
ps5.nop(addr, 5)
ps5.hook(addr, "asm...", name="h", length=None)
ps5.call(func, a1, a2, a3, a4, a5, a6) -> rax
ps5.f32(1.5)     float -> bits
ps5.protect(addr, size, "rwx")

FIND
ps5.module("eboot.bin")     ps5.module() = the game
ps5.maps()
ps5.aob("48 8B ?? 05", module="main", index=1) -> addr | None
ps5.aob_all("48 8B ?? 05", limit=32) -> [addr, ...]
ps5.find_value(99, "u32", start=None, length=None, count=100)
ps5.find_bytes("AA ?? BB", start, length, count=100)

WITH CHEATS / CONTROL
ps5.var("site")    ps5.var("x", 5)     $variables of JSON steps
ps5.param("amount")                  cheat inputs
ps5.step({"op": "patch", ...})       any JSON step
ps5.g["key"] = ...                   kept between runs
ps5.log("hp", hp)
ps5.sleep(0.5)
ps5.stopped()                        True after Stop
ps5.wait_until(lambda: ..., timeout=10)
ps5.every(1.0, fn, times=None)

struct, math, time, re are imported;  game = ps5"""


def run_code(code: str, rt, out: Callable[[str], None], stop: Optional[threading.Event] = None,
             name: str = "<script>") -> dict:
    """Run a script against a cheats.Runtime.  Returns the script's globals."""
    api = PS5(rt, out, stop)
    import re   # noqa: PLC0415
    g: dict = {"__name__": "__ps5script__", "ps5": api, "game": api, "struct": struct, "math": math,
               "time": time, "re": re, "log": api.log, "Buffer": Buffer, "ScriptStopped": ScriptStopped}
    try:
        exec(compile(code, name, "exec"), g)
    except ScriptStopped:
        out("(stopped)")
        raise
    except Exception as exc:
        tb = traceback.extract_tb(exc.__traceback__)
        line = next((f.lineno for f in reversed(tb) if f.filename == name), None)
        raise ScriptError(f"{type(exc).__name__}: {exc}" + (f"  (script line {line})" if line else "")) from exc
    return g
