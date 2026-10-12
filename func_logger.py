"""Function call logger - no breakpoint, the game keeps running at full speed.

A 5-byte jump at the function start leads to a small code cave that
  * counts the call (lock xadd on a shared index - thread safe),
  * copies all general registers, RFLAGS, RSP, the return address, XMM0-3 and the first
    5 stack arguments into a ring buffer slot,
  * runs the instructions the jump replaced (re-assembled for the cave, so RIP-relative
    and relative-branch instructions still work) and jumps back.
The tool polls the ring buffer (one or two bulk reads) and shows the calls.

Ring buffer:  +0 magic  +8 write index (= total calls)  +64 slots of 256 bytes
Slot:  0..127  r15 r14 r13 r12 r11 r10 r9 r8 rdi rsi rbp rbx rdx rcx rax rflags
       128 rsp at entry   136 return address   144..207 xmm0..xmm3
       208..247 stack args 1..5 ([rsp+8]..[rsp+40])   248 sequence (index+1, written last)
"""

from __future__ import annotations

import re
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import asmgen
import codecave
import disasm

MAGIC = 0x474F4C434E5546  # "FUNCLOG"
SLOT = 256
SLOTS = 1024             # power of two
HDR = 64
RING_SIZE = HDR + SLOTS * SLOT
REG_ORDER = ["r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rdi", "rsi", "rbp", "rbx",
             "rdx", "rcx", "rax", "rflags"]
ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]          # System V order (PS5)
_RIP_OPERAND = re.compile(r"\[\s*rip\s*[+-]\s*0x[0-9a-fA-F]+\s*\]", re.I)


class LoggerError(Exception):
    pass


@dataclass
class Call:
    index: int                       # 0-based call number
    time: float
    regs: dict[str, int]
    rsp: int
    ret: int
    xmm: list[bytes]                 # 4 x 16 bytes
    stack: list[int]                 # 5 qwords

    def arg(self, i: int) -> int:
        return self.regs[ARG_REGS[i]] if i < 6 else self.stack[i - 6] if i - 6 < len(self.stack) else 0

    def xmm_f32(self, i: int) -> float:
        return struct.unpack_from("<f", self.xmm[i])[0]

    def xmm_f64(self, i: int) -> float:
        return struct.unpack_from("<d", self.xmm[i])[0]


def parse_slot(data: bytes, index: int, now: float) -> Optional[Call]:
    if len(data) < SLOT:
        return None
    seq = struct.unpack_from("<Q", data, 248)[0]
    if seq != index + 1:
        return None                                   # being written (or overwritten) - skip
    q = struct.unpack_from("<16Q", data, 0)
    regs = dict(zip(REG_ORDER, q))
    rsp, ret = struct.unpack_from("<QQ", data, 128)
    xmm = [bytes(data[144 + 16 * i : 160 + 16 * i]) for i in range(4)]
    stack = list(struct.unpack_from("<5Q", data, 208))
    return Call(index, now, regs, rsp, ret, xmm, stack)


def stub_asm(ring: int, mask: int = SLOTS - 1) -> str:
    """Logging stub.  The 128-byte red zone is skipped first, so it is also safe mid-function."""
    widx, slots = ring + 8, ring + HDR
    return "\n".join([
        "lea rsp, [rsp - 0x80]",
        "pushfq",
        "push rax", "push rcx", "push rdx", "push rbx", "push rbp", "push rsi", "push rdi",
        "push r8", "push r9", "push r10", "push r11", "push r12", "push r13", "push r14", "push r15",
        "cld",
        "mov eax, 1",
        f"lock xadd qword ptr [rip:0x{widx:X}], rax",
        "mov rbx, rax",
        f"and eax, 0x{mask:X}",
        "shl rax, 8",
        f"lea rdi, [rip:0x{slots:X}]",
        "add rdi, rax",
        "mov rsi, rsp",
        "mov ecx, 16",
        "rep movsq",
        "lea rax, [rsp + 0x100]",
        "mov qword ptr [rdi], rax",
        "mov rax, qword ptr [rsp + 0x100]",
        "mov qword ptr [rdi + 8], rax",
        "movdqu xmmword ptr [rdi + 16], xmm0",
        "movdqu xmmword ptr [rdi + 32], xmm1",
        "movdqu xmmword ptr [rdi + 48], xmm2",
        "movdqu xmmword ptr [rdi + 64], xmm3",
        *[f"mov rax, qword ptr [rsp + 0x{0x108 + 8 * i:X}]\nmov qword ptr [rdi + {80 + 8 * i}], rax" for i in range(5)],
        "inc rbx",
        "mov qword ptr [rdi + 120], rbx",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rdi", "pop rsi", "pop rbp", "pop rbx", "pop rdx", "pop rcx", "pop rax",
        "popfq",
        "lea rsp, [rsp + 0x80]",
    ])


def relocate(stolen: list) -> str:
    """The replaced instructions as assembly that is correct at any address (near the original)."""
    out = []
    for ins in stolen:
        text = ins.text
        if ins.ripref is not None and _RIP_OPERAND.search(text):
            out.append(_RIP_OPERAND.sub(f"[rip:0x{ins.ripref:X}]", text, count=1))
        elif ins.target is not None:
            out.append(text)                          # capstone prints the absolute target
        else:
            out.append(".byte " + ", ".join(f"0x{b:02X}" for b in ins.raw))
    return "\n".join(out)


def _alloc_near(client, pid: int, site: int, size: int) -> int:
    for delta in (-0x4000000, 0x4000000, -0x10000000, 0x10000000, -0x40000000, 0x40000000):
        hint = (site + delta) & ~0x3FFF
        if hint <= 0:
            continue
        try:
            a = client.alloc_hinted(pid, hint, size)
        except Exception:
            continue
        if codecave.in_near_range(site, a):
            return a
        try:
            client.free(pid, a, size)
        except Exception:
            pass
    raise LoggerError("no free memory within 2 GB of the function")


@dataclass
class FuncLogger:
    client: object
    pid: int
    addr: int
    name: str = ""
    cave: int = 0
    ring: int = 0
    cave_size: int = 0
    orig: bytes = b""
    active: bool = False
    seen: int = 0                    # calls already read
    lost: int = 0                    # overwritten before they were read
    notes: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ---------------------------------------------------------------- install
    def start(self, bps=()) -> None:
        c, pid, addr = self.client, self.pid, self.addr
        insns, _ = disasm.disassemble(c, pid, addr, 0x40, 16)
        chk = codecave.check_cave(insns, 0, far=False, bps=bps)
        if not chk.ok:
            raise LoggerError(f"cannot hook 0x{addr:X}: {chk.reason}")
        if chk.warnings:
            raise LoggerError("; ".join(chk.warnings))
        self.notes = list(chk.notes)
        stolen = chk.stolen
        self.orig = chk.orig
        resume = addr + chk.length

        self.ring = _alloc_near(c, pid, addr, RING_SIZE)
        hdr = struct.pack("<QQ", MAGIC, 0).ljust(HDR, b"\0")
        c.write(pid, self.ring, hdr)
        for off in range(0, SLOTS * SLOT, 0x10000):                # zeroed slots (seq = 0)
            c.write(pid, self.ring + HDR + off, bytes(min(0x10000, SLOTS * SLOT - off)))

        asm = stub_asm(self.ring) + "\n" + relocate(stolen)
        probe = codecave.assemble_cave(asm, addr, lambda s: 0, resume)
        self.cave_size = (len(probe) + 0x40 + 0xF) & ~0xF
        self.cave = _alloc_near(c, pid, addr, self.cave_size)
        code = codecave.assemble_cave(asm, self.cave, lambda s: 0, resume)
        if len(code) > self.cave_size:
            raise LoggerError("stub grew while relocating - try again")
        c.write(pid, self.cave, code.ljust(self.cave_size, b"\xCC"))
        c.protect(pid, self.cave, self.cave_size, 5)              # r-x
        cur = c.read(pid, addr, len(self.orig))
        if cur != self.orig:
            raise LoggerError(f"bytes at 0x{addr:X} changed while installing - another hook or breakpoint is there")
        c.write(pid, addr, codecave.hook_bytes(addr, self.cave, len(self.orig), False))
        self.active, self.seen, self.lost = True, 0, 0

    # ---------------------------------------------------------------- read
    def poll(self, max_calls: int = SLOTS) -> list[Call]:
        """New calls since the last poll (oldest first)."""
        with self._lock:
            c, pid = self.client, self.pid
            widx = struct.unpack("<Q", c.read(pid, self.ring + 8, 8))[0]
            if widx <= self.seen:
                return []
            first = self.seen
            if widx - first > SLOTS - 8:                            # ring lapped us: keep the newest
                first = widx - (SLOTS - 8)
                self.lost += first - self.seen
            first = max(first, widx - max_calls)
            n = widx - first
            s0 = first & (SLOTS - 1)
            parts = []
            if s0 + n <= SLOTS:
                parts.append(c.read(pid, self.ring + HDR + s0 * SLOT, n * SLOT))
            else:
                k = SLOTS - s0
                parts.append(c.read(pid, self.ring + HDR + s0 * SLOT, k * SLOT))
                parts.append(c.read(pid, self.ring + HDR, (n - k) * SLOT))
            blob = b"".join(parts)
            now = time.time()
            out: list[Call] = []
            for i in range(n):
                call = parse_slot(blob[i * SLOT : (i + 1) * SLOT], first + i, now)
                if call is None:
                    break                                           # still being written: next poll
                out.append(call)
            self.seen = first + len(out)
            return out

    def total(self) -> int:
        return struct.unpack("<Q", self.client.read(self.pid, self.ring + 8, 8))[0]

    # ---------------------------------------------------------------- remove
    def stop(self) -> None:
        if not self.active:
            return
        c, pid = self.client, self.pid
        c.write(pid, self.addr, self.orig)
        self.active = False
        # a thread may still be inside the cave for a moment: free the memory a little later
        cave, cs, ring = self.cave, self.cave_size, self.ring

        def later() -> None:
            time.sleep(2.0)
            for a, n in ((cave, cs), (ring, RING_SIZE)):
                try:
                    c.free(pid, a, n)
                except Exception:
                    pass
        threading.Thread(target=later, daemon=True).start()
