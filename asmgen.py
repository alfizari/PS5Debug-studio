"""x86-64 assembler for the 'code' cheat step, built on keystone-engine.

Lets a cheat embed real assembly (like Cheat Engine's auto-assembler) instead
of raw hex. Supports:
  - normal NASM-ish syntax, labels, jumps/calls to those labels
  - cheat expressions, substituted with a literal hex immediate before
    assembling. Bare forms work directly:  mov rdi, @buf0   /
    mov rax, module(eboot.bin)   /   mov esi, $item   (add +0x10 etc. freely,
    the assembler does the arithmetic). The braced form {expr} still works
    and is needed for anything fancier, e.g. {[module(eboot.bin)+0x4A1C00]+0x20}
    or buffer names containing '-'. Text after ';' is a comment and is dropped before assembling.
  - auto-appends `ret` if the code doesn't already end in a return/jump, so
    a one-line snippet like `mov [rdi], rsi` is a valid callable function
"""

from __future__ import annotations

import re
from typing import Callable, Optional

try:
    import keystone as _ks
except ImportError:  # pragma: no cover
    _ks = None

TOKEN = re.compile(r"\{([^{}]+)\}")
# bare (brace-less) expression atoms usable straight in assembly text
BARE = re.compile(r"@[A-Za-z_][\w.]*|module\([^)]*\)|\$[A-Za-z_][\w.]*")
_END_OPS = re.compile(r"^\s*(ret\w*|jmp\b|iretq?)\b", re.IGNORECASE)
_LABEL = re.compile(r"^\s*[A-Za-z_.$][\w.$]*\s*:\s*$")


class AsmError(Exception):
    pass


def _require_keystone() -> None:
    if _ks is None:
        raise AsmError(
            "keystone-engine is not installed. Run: pip install keystone-engine"
        )


def substitute(code: str, resolve: Callable[[str], int]) -> str:
    """Replace {expr} and bare @buf / module(x) / $var with hex literals
    computed by `resolve`. ';' comments are removed (keystone would otherwise
    read ';' as a statement separator and fail)."""

    def _value(expr: str, shown: str) -> str:
        try:
            value = resolve(expr)
        except Exception as exc:
            raise AsmError(f"bad expression {shown}: {exc}") from exc
        return f"0x{value & 0xFFFFFFFFFFFFFFFF:X}"

    def _brace(m: re.Match) -> str:
        expr = m.group(1).strip()
        return _value(expr, "{" + expr + "}")

    def _bare(m: re.Match) -> str:
        return _value(m.group(0), m.group(0))

    out = []
    for line in code.split("\n"):
        # keystone treats ';' as a statement separator, not a comment, so drop
        # the comment here (NASM style) before assembling
        body = line.split(";", 1)[0]
        body = TOKEN.sub(_brace, body)
        body = BARE.sub(_bare, body)
        out.append(body.rstrip())
    return "\n".join(out)


def needs_ret(code: str) -> bool:
    last = ""
    for line in code.splitlines():
        line = line.split(";", 1)[0].strip()
        if not line or _LABEL.match(line):
            continue
        last = line
    return not (last and _END_OPS.match(last))


def ensure_ret(code: str, auto: bool = True) -> str:
    if auto and needs_ret(code):
        code = code.rstrip() + "\nret\n"
    return code


def assemble(code: str, address: int = 0) -> bytes:
    """Assemble x86-64 text to machine code. `address` anchors label math."""
    _require_keystone()
    ks = _ks.Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_64)
    try:
        encoding, count = ks.asm(code, addr=address)
    except _ks.KsError as exc:
        raise AsmError(f"assembler error: {exc}") from exc
    if encoding is None or count == 0:
        raise AsmError("assembled to zero bytes (empty or label-only code?)")
    return bytes(encoding)


def pad(data: bytes, size: Optional[int], align: int = 16) -> bytes:
    """Pad with NOPs (0x90) up to `size`, or up to the next `align` bytes."""
    target = size if size else ((len(data) + align - 1) // align) * align
    if target < len(data):
        raise AsmError(f"assembled code is {len(data)} bytes, requested size is {target}")
    return data + b"\x90" * (target - len(data))


# ---------------------------------------------------------------- auto stack frame
_RSP_OFF = re.compile(r"\[\s*rsp\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*\]", re.IGNORECASE)
_MANAGES_STACK = re.compile(r"^\s*(sub\s+rsp\b|add\s+rsp\b|and\s+rsp\b|push\w*\b|enter\b|lea\s+rsp\b|mov\s+rsp\b)",
                            re.IGNORECASE)
_CALL = re.compile(r"^\s*call\b", re.IGNORECASE)
_RET = re.compile(r"^\s*ret\w*\b", re.IGNORECASE)


def auto_frame(code: str) -> tuple[str, int]:
    """Give callable code a proper stack frame when it needs one and has none.

    Code that calls functions or writes stack arguments ([rsp+X]) without
    reserving space first would (a) overwrite its own return address and the
    caller's stack and (b) call with a misaligned stack.  This inserts
        sub rsp, N      at the start   (N covers the highest [rsp+X] used, keeps rsp 16-byte aligned)
        add rsp, N      before every ret (one is appended if the code has none)
    Returns (code, N); N == 0 means the code was left alone (it does not need a
    frame, or it already manages rsp itself with sub/push/...)."""
    lines = code.split("\n")
    body = [ln.split(";", 1)[0] for ln in lines]
    if any(_MANAGES_STACK.match(b) for b in body):
        return code, 0
    uses_stack = False
    max_off = -8
    for b in body:
        for m in _RSP_OFF.finditer(b):
            uses_stack = True
            off = int(m.group(1), 0) if m.group(1) else 0
            max_off = max(max_off, off)
    has_call = any(_CALL.match(b) for b in body)
    if not (uses_stack or has_call):
        return code, 0
    area = (max_off + 8 + 15) & ~15 if max_off >= 0 else 0
    frame = max(0x28, area + 8)            # entry rsp = 8 mod 16  ->  after the sub: 0 mod 16
    out = [f"sub rsp, 0x{frame:X}"]      # (no ';' comment here: the text is assembled as-is)
    for ln, b in zip(lines, body):
        if _RET.match(b):
            out.append(f"add rsp, 0x{frame:X}")
        out.append(ln)
    if needs_ret("\n".join(body)):
        out += [f"add rsp, 0x{frame:X}", "ret"]
    return "\n".join(out), frame
