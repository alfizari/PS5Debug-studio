"""Call-stack unwinding without debug info.

The console's RBP-chain walk only works while every function on the stack keeps a frame pointer.
Game code is often built with frameless functions (no `push rbp; mov rbp, rsp`), and then the walk
skips frames - typically the direct caller of the function you stopped in.

This unwinder works out, for each frame, where the return address is stored:

1. Forward: from the current instruction, follow straight-line code to the `ret` (pops, add rsp,
   leave ...).  Exact when there is no branch in between - e.g. stopped in an epilogue.
2. Backward: decode the function's entry block from its (estimated) start up to the current
   instruction and add up what it pushed / subtracted from rsp.  With an rbp frame set up, the
   return address is at rbp + 8 instead (works with stack alignment and alloca too).

Each step yields the caller's rip / rsp / rbp, and the next frame is unwound the same way.
Pure functions: memory comes from callbacks, so this is testable off-console.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

try:
    import capstone as _cs
except ImportError:  # pragma: no cover
    _cs = None

M64 = 0xFFFFFFFFFFFFFFFF
_MD = None
_NUM = r"(0x[0-9a-fA-F]+|\d+)"
_RSP_DISP = re.compile(r"^rsp, (?:qword ptr )?\[rsp(?: ([+-]) " + _NUM + r")?\]$")
_RBP_FROM_RSP = re.compile(r"^rbp, (?:qword ptr )?\[rsp(?: ([+-]) " + _NUM + r")?\]$")
_RSP_FROM_RBP = re.compile(r"^rsp, (?:qword ptr )?\[rbp(?: ([+-]) " + _NUM + r")?\]$")
_IMM = re.compile(r"^" + _NUM + r"$")
_BRANCH = ("j", "loop")


def _md():
    global _MD
    if _MD is None and _cs is not None:
        _MD = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
    return _MD


def _disp(m) -> int:
    if not m.group(1):
        return 0
    v = int(m.group(2), 0)
    return v if m.group(1) == "+" else -v


def _imm(s: str) -> Optional[int]:
    m = _IMM.match(s.strip())
    return int(m.group(1), 0) if m else None


def _writes_rsp(mn: str, ops: str) -> bool:
    if mn in ("push", "pop", "call", "ret", "leave", "enter", "pushfq", "popfq") or mn.startswith("push") or mn.startswith("pop"):
        return True
    dst = ops.split(",", 1)[0].strip()
    return dst in ("rsp", "esp", "sp") and mn not in ("cmp", "test")


@dataclass
class Prologue:
    d: int                      # bytes below the entry rsp at the stop point (entry_rsp = rsp + d)
    rbp_d: Optional[int]        # rbp = entry_rsp - rbp_d once the frame pointer is set up
    saved_rbp_d: Optional[int]  # caller's rbp saved at entry_rsp - saved_rbp_d
    ok: bool                    # False: an rsp change we cannot follow (and no frame pointer)


def analyze_entry(code: bytes, start: int, stop: int, max_insns: int = 64) -> Prologue:
    """Walk the entry block of a function (start .. first branch, or `stop`) and track rsp."""
    d, rbp_d, saved, ok = 0, None, None, True
    md = _md()
    if md is None:
        return Prologue(0, None, None, False)
    n = 0
    for ins in md.disasm(code, start):
        if ins.address >= stop or n >= max_insns:
            break
        n += 1
        mn, ops = ins.mnemonic, ins.op_str.strip()
        if mn == "push":
            d += 8
            if ops == "rbp" and saved is None:
                saved = d
        elif mn == "pushfq":
            d += 8
        elif mn == "pop":
            d -= 8
        elif mn in ("sub", "add") and ops.startswith("rsp,"):
            v = _imm(ops.split(",", 1)[1])
            if v is None:
                if rbp_d is None:
                    ok = False
                break                                    # sub rsp, rax (alloca / probe): stop here
            d += v if mn == "sub" else -v
        elif mn == "lea" and _RSP_DISP.match(ops):
            d -= _disp(_RSP_DISP.match(ops))
        elif mn == "mov" and ops == "rbp, rsp":
            rbp_d = d
        elif mn == "lea" and _RBP_FROM_RSP.match(ops):
            rbp_d = d - _disp(_RBP_FROM_RSP.match(ops))
        elif mn == "call":
            continue                                     # returns with rsp unchanged
        elif mn.startswith(_BRANCH) or mn.startswith("ret") or mn in ("ud2", "int3", "hlt"):
            break                                        # end of the entry block
        elif _writes_rsp(mn, ops):
            if rbp_d is None:
                ok = False                               # and rsp, -32 etc. without a frame pointer
            break
    return Prologue(d, rbp_d, saved, ok)


@dataclass
class Exit:
    ret_slot: int               # address holding the return address
    rbp: int                    # caller's rbp after the ret


def forward_to_ret(code: bytes, rip: int, rsp: int, rbp: int, read_u64: Callable[[int], Optional[int]],
                   max_insns: int = 24) -> Optional[Exit]:
    """Simulate straight-line code from rip to its ret (rsp / rbp only).  None at any branch or unknown."""
    md = _md()
    if md is None:
        return None
    n = 0
    for ins in md.disasm(code, rip):
        n += 1
        if n > max_insns:
            return None
        mn, ops = ins.mnemonic, ins.op_str.strip()
        if mn.startswith("ret"):
            return Exit(rsp, rbp)
        if mn == "pop":
            if ops == "rbp":
                v = read_u64(rsp)
                if v is None:
                    return None
                rbp = v
            rsp = (rsp + 8) & M64
        elif mn == "push":
            rsp = (rsp - 8) & M64
        elif mn == "leave":
            rsp = rbp
            v = read_u64(rsp)
            if v is None:
                return None
            rbp, rsp = v, (rsp + 8) & M64
        elif mn in ("add", "sub") and ops.startswith("rsp,"):
            v = _imm(ops.split(",", 1)[1])
            if v is None:
                return None
            rsp = (rsp + (v if mn == "add" else -v)) & M64
        elif mn == "lea" and _RSP_DISP.match(ops):
            rsp = (rsp + _disp(_RSP_DISP.match(ops))) & M64
        elif mn == "lea" and _RSP_FROM_RBP.match(ops):
            rsp = (rbp + _disp(_RSP_FROM_RBP.match(ops))) & M64
        elif mn == "mov" and ops == "rsp, rbp":
            rsp = rbp
        elif mn in ("call", "jmp", "ud2", "int3", "hlt", "syscall") or mn.startswith(_BRANCH):
            return None                                  # control flow: not straight-line any more
        elif ops.split(",", 1)[0].strip() in ("rbp", "ebp", "bp") and mn not in ("cmp", "test"):
            return None                                  # rbp changed in a way we do not follow
        elif _writes_rsp(mn, ops):
            return None
    return None


def unwind_one(rip: int, rsp: int, rbp: int, func_start: Optional[int], entry_code: bytes,
               code_at_rip: bytes, read_u64: Callable[[int], Optional[int]]) -> Optional[tuple[int, int, int, int, str]]:
    """One frame up.  Returns (ret_addr, ret_slot, caller_rsp, caller_rbp, how) or None.

    `entry_code` = bytes from func_start (up to rip), `code_at_rip` = bytes from rip on."""
    # straight-line to a ret: exact (for outer frames only when the call returns into an epilogue)
    if code_at_rip:
        ex = forward_to_ret(code_at_rip, rip, rsp, rbp, read_u64)
        if ex is not None:
            ra = read_u64(ex.ret_slot)
            if ra is not None:
                return ra, ex.ret_slot, (ex.ret_slot + 8) & M64, ex.rbp, "epilogue"
    if func_start is None or (not entry_code and rip != func_start):
        return None
    pro = analyze_entry(entry_code, func_start, rip)
    # outer frames: rip is a return address, so the entry block is complete (call was after it)
    if pro.rbp_d is not None:
        entry = (rbp + pro.rbp_d) & M64
        how = "frame pointer"
    elif pro.ok:
        entry = (rsp + pro.d) & M64
        how = "prologue"
    else:
        return None
    ra = read_u64(entry)
    if ra is None:
        return None
    caller_rbp = rbp
    if pro.saved_rbp_d is not None:
        v = read_u64((entry - pro.saved_rbp_d) & M64)      # push rbp stored it at entry - saved_d
        if v is None:
            return None
        caller_rbp = v
    return ra, entry, (entry + 8) & M64, caller_rbp, how


@dataclass
class Frame:
    ret: int                    # return address (rip of the caller)
    slot: int                   # stack address holding it
    how: str                    # "epilogue" / "prologue" / "frame pointer"
    call: object = None         # the CALL instruction before `ret` (from `call_at`)
    rsp: int = 0                # caller's rsp / rbp after the return
    rbp: int = 0


def walk(rip: int, rsp: int, rbp: int,
         code_info: Callable[[int], tuple[Optional[int], bytes, bytes]],
         read_u64: Callable[[int], Optional[int]],
         call_at: Callable[[int], object],
         max_frames: int = 32) -> list[Frame]:
    """Unwind as far as each step checks out.  code_info(addr) -> (function start, bytes from the
    start up to addr, bytes from addr on); call_at(ret) -> the CALL before ret, or None."""
    out: list[Frame] = []
    for _ in range(max_frames):
        fs, entry_code, here = code_info(rip)
        r = unwind_one(rip, rsp, rbp, fs, entry_code, here, read_u64)
        if r is None:
            break
        ret, slot, nrsp, nrbp, how = r
        if slot < rsp or (out and slot <= out[-1].slot):
            break                                       # must move up the stack
        call = call_at(ret)
        if call is None:
            break                                       # not a return address: our guess was wrong
        out.append(Frame(ret, slot, how, call, nrsp, nrbp))
        rip, rsp, rbp = ret, nrsp, nrbp
    return out
