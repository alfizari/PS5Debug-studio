"""Disassembly helpers shared by the Disassembler and Debugger tabs.

Text comes from capstone (pip install capstone). The ps5debug-NG server also
has a built-in Zydis decoder, but it only returns instruction lengths and
control-flow metadata (not text) - we use that as a fallback so the tabs still
show real instruction boundaries / CALL / RET / JMP markers when capstone is
not installed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

try:
    import capstone as _cs
except ImportError:  # pragma: no cover
    _cs = None

K_CALL, K_RET, K_JMP, K_JCC = 0x01, 0x02, 0x04, 0x08  # same bits as the server's `kind`

_IMM = re.compile(r"^(?:0x)?([0-9a-fA-F]+)$")
_RIPREL = re.compile(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]")
M64 = 0xFFFFFFFFFFFFFFFF


@dataclass
class Insn:
    addr: int
    size: int
    raw: bytes
    text: str
    kind: int = 0
    target: Optional[int] = None  # direct call/jmp/jcc destination
    ripref: Optional[int] = None  # absolute address of a [rip+disp] operand

    @property
    def mnemonic(self) -> str:
        return self.text.split(" ", 1)[0].lower()

    def hexbytes(self) -> str:
        return " ".join(f"{b:02X}" for b in self.raw)

    def note(self) -> str:
        if self.target is not None:
            return f"-> {self.target:X}"
        if self.ripref is not None:
            return f"[{self.ripref:X}]"
        return ""


def have_capstone() -> bool:
    return _cs is not None


def _classify(mnemonic: str) -> int:
    m = mnemonic.lower()
    if m == "call":
        return K_CALL
    if m.startswith("ret") or m in ("iret", "iretq", "iretd"):
        return K_RET
    if m == "jmp":
        return K_JMP
    if m.startswith("j") or m.startswith("loop"):
        return K_JCC
    return 0


def decode(data: bytes, addr: int, max_insns: int = 256) -> list[Insn]:
    """Decode `data` (located at `addr`) into at most `max_insns` instructions."""
    if _cs is None:
        raise RuntimeError("capstone is not installed. Run: pip install capstone")
    md = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
    md.skipdata = True  # undecodable bytes show up as ".byte 0x.." instead of stopping
    out: list[Insn] = []
    for ins in md.disasm(data, addr):
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        kind = _classify(ins.mnemonic)
        target = None
        if kind & (K_CALL | K_JMP | K_JCC):
            m = _IMM.match(ins.op_str.strip())
            if m:
                target = int(m.group(1), 16)
        ripref = None
        m = _RIPREL.search(ins.op_str)
        if m:
            disp = int(m.group(2), 0)
            ripref = (ins.address + ins.size + (disp if m.group(1) == "+" else -disp)) & M64
        out.append(Insn(ins.address, ins.size, bytes(ins.bytes), text, kind, target, ripref))
        if len(out) >= max_insns:
            break
    return out


def decode_from_server(client, pid: int, data: bytes, addr: int, max_insns: int) -> list[Insn]:
    """Fallback: boundaries + kind from the server's Zydis decoder, bytes from `data`."""
    entries = client.disasm_region(pid, addr, len(data), max_insns)
    out: list[Insn] = []
    for e in entries:
        off = e.addr - addr
        raw = data[off : off + e.length] if 0 <= off < len(data) else b""
        if e.kind & 0x01:
            label = "call"
        elif e.kind & 0x02:
            label = "ret"
        elif e.kind & 0x04:
            label = "jmp"
        elif e.kind & 0x08:
            label = "jcc"
        else:
            label = "(install capstone for text)"
        ripref = e.rip_rel_target or None
        kind = e.kind & 0x0F
        out.append(Insn(e.addr, e.length, raw, label, kind, None, ripref))
    return out


def disassemble(
    client,
    pid: int,
    addr: int,
    length: int = 0x400,
    max_insns: int = 128,
    overrides: Optional[dict[int, int]] = None,
) -> tuple[list[Insn], bool]:
    """Read memory and decode it. Returns (instructions, used_capstone).

    `overrides` maps address -> original byte, so software breakpoints (0xCC the
    debugger wrote into memory) still disassemble as the real instruction."""
    data = b""
    last_exc: Optional[Exception] = None
    for n in (length, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10):
        if n > length:
            continue
        try:
            data = client.read(pid, addr, n)
            break
        except Exception as exc:  # unreadable tail of a mapping - try shorter
            last_exc = exc
    if not data:
        raise RuntimeError(f"cannot read memory at 0x{addr:X}: {last_exc}")
    if overrides:
        buf = bytearray(data)
        for a, b in overrides.items():
            if addr <= a < addr + len(buf):
                buf[a - addr] = b
        data = bytes(buf)
    if _cs is not None:
        return decode(data, addr, max_insns), True
    return decode_from_server(client, pid, data, addr, max_insns), False


def call_site_from_bytes(data: bytes, ret_addr: int, overrides: Optional[dict[int, int]] = None) -> Optional[Insn]:
    """`data` = the 8 bytes before `ret_addr`.  The CALL that returns to `ret_addr`, if there is one."""
    if _cs is None or len(data) < 8:
        return None
    if overrides:
        buf = bytearray(data)
        for a, b in overrides.items():
            if ret_addr - 8 <= a < ret_addr:
                buf[a - (ret_addr - 8)] = b
        data = bytes(buf)
    for size in (5, 6, 2, 3, 4, 7, 8):  # common call encodings first
        start = ret_addr - size
        chunk = data[8 - size :]
        for ins in decode(chunk, start, 1):
            if ins.kind == K_CALL and ins.addr + ins.size == ret_addr:
                return ins
    return None


def find_call_site(client, pid: int, ret_addr: int, overrides: Optional[dict[int, int]] = None) -> Optional[Insn]:
    """If `ret_addr` is the instruction right after a CALL, return that CALL."""
    if _cs is None:
        return None
    try:
        data = client.read(pid, ret_addr - 8, 8)
    except Exception:
        return None
    return call_site_from_bytes(data, ret_addr, overrides)


# ------------------------------------------------------------------ function starts
# Compiled game code (clang) puts functions on 16-byte boundaries with int3 (0xCC) padding between them.
_STRONG_PROLOGUES = (b"\x55\x48\x89\xe5", b"\x55\x48\x8b\xec", b"\x41\x57\x41\x56", b"\x41\x56\x41\x55",
                     b"\x55\x41\x57", b"\x55\x41\x56", b"\x53\x48\x83\xec", b"\x48\x83\xec", b"\x48\x81\xec")


_MD_STRICT = None
_WEAK_PROLOGUE_1 = {0x50, 0x53, 0x55}                    # push rax / rbx / rbp
_WEAK_PROLOGUE_2 = {b"\x41\x54", b"\x41\x55", b"\x41\x56", b"\x41\x57"}  # push r12..r15


def _lands_on(data: bytes, start: int, target: int) -> bool:
    """Do the instructions decoded from `start` end exactly at `target` (a valid boundary)?"""
    if _cs is None:
        return True
    global _MD_STRICT
    if _MD_STRICT is None:
        _MD_STRICT = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)     # no skipdata: bad bytes stop the walk
    pos = start
    try:
        for ins in _MD_STRICT.disasm(data, start):
            pos = ins.address + ins.size
            if pos >= target:
                break
    except Exception:
        return False
    return pos == target


def _all_nops(b: bytes) -> bool:
    """Is `b` empty or made only of nop instructions (alignment padding)?"""
    if not b:
        return True
    if _cs is None:
        return all(x == 0x90 for x in b)
    _lands_on(b"", 0, 0)                                  # make sure _MD_STRICT exists
    pos = 0
    for ins in _MD_STRICT.disasm(b, 0):
        if ins.mnemonic not in ("nop", "xchg") or (ins.mnemonic == "xchg" and ins.op_str != "ax, ax"):
            return False
        pos = ins.address + ins.size
    return pos == len(b)


def _ends_code(data: bytes, q: int) -> bool:
    """Does the code just before data[q] end the way functions end (ret, jmp, ud2, a final call)?"""
    if q >= 1 and data[q - 1] == 0xC3:
        return True
    if q >= 5 and data[q - 5] in (0xE9, 0xE8):
        return True
    if q >= 2 and (data[q - 2] == 0xEB or data[q - 2:q] == b"\x0f\x0b" or (data[q - 2] == 0xFF and 0xE0 <= data[q - 1] <= 0xE7)):
        return True
    return q >= 6 and data[q - 6] == 0xFF and data[q - 5] == 0x25


def func_start_in(data: bytes, base: int, addr: int) -> Optional[int]:
    """Best guess at the start of the function containing `addr`, from `data` = memory from `base`
    (up to `addr`; bytes past `addr` let a function that starts exactly at `addr` be recognised).
    A start is a 16-byte aligned address that follows int3 padding (or a ret + a typical prologue)
    and from which the code decodes cleanly up to `addr`.  None when nothing convincing is found."""
    end = addr - base
    if end <= 0 or end > len(data):
        return None
    p = addr & ~0xF
    while p - base > 0:
        off = p - base
        if off < len(data):
            prev = data[off - 1]
            cur = data[off]
            ok = False
            if prev == 0xCC and cur != 0xCC:
                q = off - 1
                while q > 0 and data[q - 1] == 0xCC:
                    q -= 1                                        # q = first padding byte
                while q > 0 and data[q - 1] == 0x90:
                    q -= 1                                        # clang puts a nop after a no-return call
                ok = _ends_code(data, q)                         # CC bytes also occur inside instructions
            elif cur != 0xCC:
                strong = any(data.startswith(pr, off) for pr in _STRONG_PROLOGUES)
                weak = data[off] in _WEAK_PROLOGUE_1 or data[off:off + 2] in _WEAK_PROLOGUE_2
                # nop padding (90, 66 90, 0f 1f .., up to 31 bytes) after the end of the previous function;
                # with a full prologue there may be no padding at all
                for q in range(off, max(0, off - 31) - 1, -1):
                    if q == off and not strong:
                        continue
                    if _ends_code(data, q) and _all_nops(data[q:off]):
                        # after a ret + padding it is a new function even without a prologue (leaf);
                        # after a jmp + padding it could be an aligned loop head, so want a prologue
                        ok = strong or weak or (q < off and data[q - 1] == 0xC3)
                        break
            if ok and _lands_on(data[off:end], p, addr):
                return p
        p -= 16
    return None
