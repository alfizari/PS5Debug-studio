"""Code caves: hook an instruction, run your own assembly instead, jump back.

How a hook works
  1. The instruction(s) at the hook address are *stolen*: enough whole
     instructions are taken to fit a jump (5 bytes near / 14 bytes far).
  2. Your assembly (pre-filled with the stolen instructions, so you edit them)
     is assembled into a cave: a fresh executable buffer.  A far jump back to
     the instruction after the stolen bytes is appended automatically.
  3. The hook site is overwritten with `jmp cave` (+ NOP padding).
  4. Disabling writes the original bytes back (the cave stays allocated and is
     reused the next time).

Cave source syntax = normal assembly (keystone) plus the usual cheat
expressions (@buf, $var, module(x)+0x10, {expr}).  One extra form exists
for RIP-relative operands, because a copied `mov eax, [rip+0x1234]` would
point to the wrong place once it lives in the cave:

    mov eax, dword ptr [rip:module(eboot.bin)+0x4A1C00]

meaning "RIP-relative access to that absolute address"; the displacement is
computed for the cave position when assembling.  The disassembler generates
this form for you.

This module has no UI code; cheats.py uses it for the `hook` step and
codecave_dialog.py for the Disassembler dialog.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

import asmgen
from asmgen import AsmError

M64 = (1 << 64) - 1
JMP_NEAR = 5     # E9 rel32
JMP_FAR = 14     # FF 25 00000000 + imm64   (clobbers nothing)
K_RET, K_JMP = 0x02, 0x04   # same bits as disasm.py (kept local: no import cycle)


class CaveError(Exception):
    pass


# ---------------------------------------------------------------- jumps
def jump_len(far: bool) -> int:
    return JMP_FAR if far else JMP_NEAR


def far_jump(target: int) -> bytes:
    return b"\xFF\x25\x00\x00\x00\x00" + (target & M64).to_bytes(8, "little")


def in_near_range(src: int, dst: int) -> bool:
    return -0x80000000 <= dst - (src + JMP_NEAR) <= 0x7FFFFFFF


def near_jump(src: int, dst: int) -> bytes:
    if not in_near_range(src, dst):
        raise CaveError(f"cave 0x{dst:X} is more than 2 GB from the hook 0x{src:X} - use a far jump")
    return b"\xE9" + (dst - (src + JMP_NEAR)).to_bytes(4, "little", signed=True)


def hook_bytes(addr: int, cave: int, stolen_len: int, far: bool) -> bytes:
    """What is written over the stolen bytes: the jump, then NOPs."""
    j = far_jump(cave) if far else near_jump(addr, cave)
    if stolen_len < len(j):
        raise CaveError(f"only {stolen_len} byte(s) stolen, the jump needs {len(j)}")
    return j + b"\x90" * (stolen_len - len(j))


# ------------------------------------------------------------- assembly
_RIPMARK = re.compile(r"\[\s*rip\s*:\s*([^\]]+?)\s*\]", re.IGNORECASE)
_ARITH = re.compile(r"\s*(0[xX][0-9a-fA-F]+|\d+|[+\-*()])")
_LABEL = re.compile(r"^\s*[A-Za-z_.$][\w.$]*\s*:\s*$")


def _eval_arith(text: str) -> int:
    toks: list[str] = []
    s, pos = text.strip(), 0
    while pos < len(s):
        m = _ARITH.match(s, pos)
        if not m:
            raise AsmError(f"bad RIP-relative target '{text}'")
        toks.append(m.group(1))
        pos = m.end()
    try:
        return int(eval(" ".join(toks), {"__builtins__": {}}, {})) & M64  # tokens are numbers/operators only
    except Exception:
        raise AsmError(f"bad RIP-relative target '{text}'") from None


def _has_code(lines: list[str]) -> bool:
    return any(l.strip() and not _LABEL.match(l) for l in lines)


def assemble_at(code: str, base: int, resolve: Callable[[str], int]) -> bytes:
    """Assemble `code` to run at `base`.  [rip:EXPR] operands become RIP-relative to EXPR.

    A RIP-relative displacement counts from the END of its instruction.  Every such line gets a
    label after it, and a table of those labels' addresses is appended (".quad"), so ONE assembly
    pass tells where each instruction ends - forward jumps to labels defined later work too.
    The displacement field is always 4 bytes, so filling it in never moves anything."""
    lines = asmgen.substitute(code, resolve).split("\n")
    marks: dict[int, int] = {}
    plain: list[str] = []
    for i, line in enumerate(lines):
        found = _RIPMARK.findall(line)
        if len(found) > 1:
            raise AsmError(f"line {i + 1}: more than one [rip:...] operand")
        if found:
            marks[i] = _eval_arith(found[0])
            line = _RIPMARK.sub("[rip + 0]", line, count=1)
        plain.append(line)
    if not _has_code(plain):
        return b""
    if not marks:
        return asmgen.assemble("\n".join(plain), base)

    order = sorted(marks)
    probe = []
    for i, line in enumerate(plain):
        probe.append(line)
        if i in marks:
            probe.append(f"__ripend_{i}:")
    probe += [f".quad __ripend_{i}" for i in order]
    try:
        raw = asmgen.assemble("\n".join(probe), base)
    except AsmError as exc:
        raise AsmError(f"cannot place the [rip:...] operands ({exc})") from None
    table = raw[len(raw) - 8 * len(order):]
    for k, i in enumerate(order):
        end = int.from_bytes(table[8 * k:8 * k + 8], "little")
        disp = marks[i] - end
        if not -0x80000000 <= disp <= 0x7FFFFFFF:
            raise AsmError(f"line {i + 1}: 0x{marks[i]:X} is too far for a RIP-relative operand")
        plain[i] = plain[i].replace("[rip + 0]", f"[rip {'-' if disp < 0 else '+'} 0x{abs(disp):X}]", 1)
    out = asmgen.assemble("\n".join(plain), base)
    if len(out) != len(raw) - 8 * len(order):
        raise AsmError("RIP-relative operands changed the code size - report this cave")
    return out


def assemble_cave(code: str, base: int, resolve: Callable[[str], int], resume: int) -> bytes:
    """Assemble `code` to run at `base`, then append a far jump to `resume`."""
    return assemble_at(code, base, resolve) + far_jump(resume)


def dollar_vars(code: str) -> list[str]:
    """$names used by the assembly (they become cheat inputs)."""
    seen: list[str] = []
    for line in code.split("\n"):
        for n in re.findall(r"\$([A-Za-z_]\w*)", line.split(";", 1)[0]):
            if n != "ret" and n not in seen:
                seen.append(n)
    return seen


# ---------------------------------------------------- check + original text
@dataclass
class CaveCheck:
    ok: bool
    reason: str = ""
    stolen: list = field(default_factory=list)       # list[disasm.Insn]
    warnings: list[str] = field(default_factory=list)   # risky: ask before enabling
    notes: list[str] = field(default_factory=list)      # just information

    @property
    def orig(self) -> bytes:
        return b"".join(i.raw for i in self.stolen)

    @property
    def length(self) -> int:
        return sum(i.size for i in self.stolen)


def check_cave(insns: list, idx: int, far: bool = False, bps=()) -> CaveCheck:
    """Can the instruction at insns[idx] be hooked?  Needs enough whole,
    decodable instructions to fit the jump, with no function end in between."""
    need = jump_len(far)
    if not 0 <= idx < len(insns):
        return CaveCheck(False, "no instruction selected")
    stolen: list = []
    total = 0
    i = idx
    while total < need:
        if i >= len(insns):
            return CaveCheck(False, f"needs {need} bytes but the view ends first - raise the Instructions count")
        ins = insns[i]
        if stolen and ins.addr != stolen[-1].addr + stolen[-1].size:
            return CaveCheck(False, "the following instructions are not contiguous")
        if ins.text.startswith((".byte", "(")) or not ins.raw:
            return CaveCheck(False, f"undecodable bytes at 0x{ins.addr:X} (capstone needed / data, not code)")
        if stolen and stolen[-1].kind & (K_RET | K_JMP):
            return CaveCheck(False, f"the code ends (ret/jmp) after only {total} byte(s); "
                                    f"a {need}-byte jump does not fit here")
        stolen.append(ins)
        total += ins.size
        i += 1

    res = CaveCheck(True, stolen=stolen)
    start, end = stolen[0].addr, stolen[0].addr + total
    inner = {s.addr for s in stolen[1:]}
    for other in insns:
        t = other.target
        if t is not None and start < t < end and other.addr not in inner and not (start <= other.addr < end):
            res.warnings.append(
                f"0x{other.addr:X} jumps to 0x{t:X}, inside the bytes being overwritten - it would crash"
            )
    for s in stolen:
        if s.addr in set(bps):
            res.warnings.append(f"a breakpoint is set at 0x{s.addr:X}; remove it before enabling the hook")
    if len(stolen) > 1:
        res.notes.append(
            f"{len(stolen)} instructions ({total} bytes) are replaced; a thread paused in the middle of them "
            "when you enable the hook could crash"
        )
    return res


def symbolize(maps, addr: int) -> str:
    """module(name)+0xOFF when `addr` lies in a named mapping, else a hex literal."""
    for m in maps or []:
        if m.start <= addr < m.end and m.name:
            base = min(x.start for x in maps if x.name == m.name)
            return f"module({m.name})+0x{addr - base:X}"
    return f"0x{addr:X}"


_RIP_OPERAND = re.compile(r"\[rip\s*[+-]\s*(?:0x[0-9a-fA-F]+|\d+)\]")
_TRAILING_HEX = re.compile(r"0x[0-9a-fA-F]+$")


def insn_text(ins, maps) -> str:
    """Disassembly text rewritten so it keeps working at another address:
    branch targets and RIP-relative operands become absolute / module-relative."""
    t = ins.text
    if ins.ripref is not None:
        t = _RIP_OPERAND.sub(lambda _m: f"[rip:{symbolize(maps, ins.ripref)}]", t, count=1)
    elif ins.target is not None:
        m = _TRAILING_HEX.search(t)
        if m:
            t = t[: m.start()] + symbolize(maps, ins.target)
    return t


def original_text(stolen: list, maps) -> str:
    return "\n".join(insn_text(i, maps) for i in stolen)


def build_step(name: str, addr_expr: str, orig: bytes, asm: str, far: bool) -> dict:
    step = {"op": "hook", "name": name, "addr": addr_expr, "orig": orig.hex(" ").upper(), "asm": asm.rstrip("\n")}
    if far:
        step["far"] = True
    return step
