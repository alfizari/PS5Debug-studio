"""Non-UI pieces of the debugger: register layout, stop-event parsing and the
TCP 755 listener the PS5 connects back to when the target stops.

ps5debug-NG protocol notes (PROTOCOL.md 1.9):
  * Before CMD_DEBUG_ATTACH the client must already be listening on port 755.
  * Every stop (breakpoint, watchpoint, single-step, signal) is pushed as a
    fixed 1184-byte (0x4A0) packet: lwpid u32, status u32, tdname[40],
    struct reg (176), FPU/YMM (832), debug regs (128).
"""

from __future__ import annotations

import queue
import socket
import re
import struct
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

INTERRUPT_PORT = 755
PACKET_SIZE = 0x4A0

# FreeBSD amd64 `struct reg` (176 bytes): (name, offset, size)
REG_LAYOUT: list[tuple[str, int, int]] = [
    ("r15", 0, 8), ("r14", 8, 8), ("r13", 16, 8), ("r12", 24, 8), ("r11", 32, 8),
    ("r10", 40, 8), ("r9", 48, 8), ("r8", 56, 8), ("rdi", 64, 8), ("rsi", 72, 8),
    ("rbp", 80, 8), ("rbx", 88, 8), ("rdx", 96, 8), ("rcx", 104, 8), ("rax", 112, 8),
    ("trapno", 120, 4), ("fs", 124, 2), ("gs", 126, 2), ("err", 128, 4),
    ("es", 132, 2), ("ds", 134, 2), ("rip", 136, 8), ("cs", 144, 8),
    ("rflags", 152, 8), ("rsp", 160, 8), ("ss", 168, 8),
]
REG_INFO = {n: (o, sz) for n, o, sz in REG_LAYOUT}

# order shown in the registers panel
REG_DISPLAY = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags", "cs", "ss", "ds", "es", "fs", "gs",
]

FLAG_BITS = [(0, "CF"), (2, "PF"), (4, "AF"), (6, "ZF"), (7, "SF"), (8, "TF"),
             (9, "IF"), (10, "DF"), (11, "OF")]

SIGNAMES = {1: "SIGHUP", 2: "SIGINT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 8: "SIGFPE",
            9: "SIGKILL", 10: "SIGBUS", 11: "SIGSEGV", 12: "SIGSYS", 17: "SIGSTOP",
            18: "SIGTSTP", 19: "SIGCONT"}

# DR7 encodings used by CMD_DEBUG_SET_WATCHPOINT
WATCH_LEN = {1: 0, 2: 1, 8: 2, 4: 3}
WATCH_TYPE = {"exec": 0, "write": 1, "read/write": 3}


def parse_regs(blob: bytes) -> dict[str, int]:
    out: dict[str, int] = {}
    for name, off, size in REG_LAYOUT:
        out[name] = int.from_bytes(blob[off : off + size], "little")
    return out


def patch_reg(blob: bytes, name: str, value: int) -> bytes:
    off, size = REG_INFO[name]
    buf = bytearray(blob)
    buf[off : off + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
    return bytes(buf)


def flags_text(rflags: int) -> str:
    return " ".join(n for bit, n in FLAG_BITS if rflags & (1 << bit)) or "-"


@dataclass
class StopEvent:
    lwpid: int
    status: int
    tdname: str
    regs_blob: bytes
    regs: dict[str, int] = field(default_factory=dict)
    dr6: int = 0  # debug status register: bits 0-3 = hardware watchpoint 0-3 hit, bit 14 = single-step
    fpu_blob: bytes = b""  # 832-byte xsave image (XMM / YMM / MXCSR) carried by the event packet

    @property
    def signal(self) -> int:
        """Signal number from the raw wait4 status (stopped: (sig << 8) | 0x7f)."""
        if (self.status & 0xFF) == 0x7F:
            return (self.status >> 8) & 0xFF
        return self.status & 0x7F

    @property
    def signame(self) -> str:
        return SIGNAMES.get(self.signal, f"signal {self.signal}")


def parse_event(packet: bytes) -> StopEvent:
    lwpid, status = struct.unpack_from("<II", packet, 0)
    tdname = packet[8:48].split(b"\x00", 1)[0].decode("utf-8", "replace")
    blob = bytes(packet[0x30 : 0x30 + 176])
    dr6 = struct.unpack_from("<Q", packet, 0x420 + 6 * 8)[0] if len(packet) >= 0x420 + 7 * 8 else 0
    fpu = bytes(packet[0xE0 : 0xE0 + FPU_SIZE]) if len(packet) >= 0xE0 + FPU_SIZE else b""
    return StopEvent(lwpid, status, tdname, blob, parse_regs(blob), dr6, fpu)


# ---------------------------------------------------------------- XMM / YMM (xsave image)
FPU_SIZE = 832
MXCSR_OFF = 0x18
XMM_OFF = 0xA0          # 16 x 16 bytes in the FXSAVE area
YMMH_OFF = 0x240        # 16 x 16 upper halves (xsave header at 0x200, YMM_Hi128 at 0x240)
VEC_FORMATS = {         # name -> (struct char, lane bytes)
    "Float x4": ("f", 4), "Double x2": ("d", 8), "Int32 x4 (hex)": ("I", 4),
    "Int64 x2 (hex)": ("Q", 8), "Int32 x4 (dec)": ("i", 4), "Bytes x16": ("B", 1),
}
MXCSR_BITS = [(0, "IE"), (1, "DE"), (2, "ZE"), (3, "OE"), (4, "UE"), (5, "PE"), (6, "DAZ"),
              (15, "FZ")]
MXCSR_RC = ["nearest", "down", "up", "toward 0"]


def fpu_ok(fpu: bytes) -> bool:
    return len(fpu) >= XMM_OFF + 16 * 16 and any(fpu)


def vec_get(fpu: bytes, i: int, ymm: bool = False) -> bytes:
    lo = fpu[XMM_OFF + 16 * i : XMM_OFF + 16 * i + 16].ljust(16, b"\0")
    if not ymm:
        return lo
    hi = fpu[YMMH_OFF + 16 * i : YMMH_OFF + 16 * i + 16].ljust(16, b"\0")
    return lo + hi


def vec_set(fpu: bytes, i: int, data: bytes) -> bytes:
    buf = bytearray(fpu)
    buf[XMM_OFF + 16 * i : XMM_OFF + 16 * i + 16] = data[:16]
    if len(data) == 32:
        if len(buf) < YMMH_OFF + 256:
            raise ValueError("the console returned only the 512-byte FXSAVE area; YMM upper halves can't be written")
        buf[YMMH_OFF + 16 * i : YMMH_OFF + 16 * i + 16] = data[16:32]
    return bytes(buf)


def mxcsr_get(fpu: bytes) -> int:
    return struct.unpack_from("<I", fpu, MXCSR_OFF)[0] if len(fpu) >= MXCSR_OFF + 4 else 0


def mxcsr_set(fpu: bytes, value: int) -> bytes:
    buf = bytearray(fpu)
    struct.pack_into("<I", buf, MXCSR_OFF, value & 0xFFFFFFFF)
    return bytes(buf)


def mxcsr_text(v: int) -> str:
    flags = [n for bit, n in MXCSR_BITS if v & (1 << bit)]
    masks = "all masked" if (v >> 7) & 0x3F == 0x3F else f"masks {(v >> 7) & 0x3F:02X}"
    return f"{' '.join(flags) or '-'}   round {MXCSR_RC[(v >> 13) & 3]}   {masks}"


def vec_hex(data: bytes) -> str:
    """High lane first, like x64dbg / Cheat Engine, grouped per 32 bits."""
    h = data[::-1].hex().upper()
    return " ".join(h[i : i + 8] for i in range(0, len(h), 8))


def _lane_text(v, ch: str) -> str:
    if ch in "fd":
        if v != v:
            return "NaN"
        if v in (float("inf"), float("-inf")):
            return "+Inf" if v > 0 else "-Inf"
        return f"{v:.7g}" if ch == "f" else f"{v:.15g}"
    if ch == "I":
        return f"{v:08X}"
    if ch == "Q":
        return f"{v:016X}"
    if ch == "B":
        return f"{v:02X}"
    return str(v)


def vec_text(data: bytes, fmt: str) -> str:
    ch, n = VEC_FORMATS[fmt]
    lanes = struct.unpack(f"<{len(data) // n}{ch}", data)
    return (" " if ch == "B" else ", ").join(_lane_text(v, ch) for v in lanes)


def vec_parse(text: str, fmt: str, old: bytes) -> bytes:
    """'0x<hex>' = the whole register; otherwise lanes low->high in the chosen format.
    Lanes left out keep their old value."""
    size = len(old)
    t = text.strip()
    parts = [p for p in re.split(r"[,\s;]+", t) if p]
    if len(parts) == 1 and parts[0].lower().startswith("0x") and fmt not in ("Int32 x4 (hex)", "Int64 x2 (hex)", "Bytes x16"):
        v = int(parts[0], 16)
        if v >> (8 * size):
            raise ValueError(f"value is wider than {8 * size} bits")
        return v.to_bytes(size, "little")
    ch, n = VEC_FORMATS[fmt]
    count = size // n
    if len(parts) > count:
        raise ValueError(f"{len(parts)} values given, the register holds {count} in {fmt}")
    lanes = list(struct.unpack(f"<{count}{ch}", old))
    for k, p in enumerate(parts):
        if ch in "fd":
            pl = p.lower()
            lanes[k] = float(pl)
        elif ch in "IQB":
            lanes[k] = int(p, 16) & ((1 << (8 * n)) - 1)
        else:
            lanes[k] = int(p, 0)
    return struct.pack(f"<{count}{ch}", *lanes)


def _module_base(maps, name: str) -> int:
    return min((m.start for m in maps if m.name == name), default=0)


def label_for(maps, addr: int) -> str:
    """'eboot.bin+0x4561E0' - offset from the lowest mapping with the same name
    (the same base module(eboot.bin) means in cheat expressions)."""
    for m in maps:
        if m.start <= addr < m.end:
            name = m.name or "anon"
            return f"{name}+0x{addr - _module_base(maps, m.name):X}"
    return ""


def prot_text(prot: int) -> str:
    return ("r" if prot & 1 else "-") + ("w" if prot & 2 else "-") + ("x" if prot & 4 else "-")


def describe_addr(maps, addr: int, relative: bool = False) -> str:
    """Info text for a value that may be an address.  Default is the ABSOLUTE
    address plus the mapping it lies in ('0x8A3939392  anon [rw-]'); with
    relative=True it is 'module+0xOFFSET' instead.  '' if it is not in any mapping."""
    if relative:
        return label_for(maps, addr)
    for m in maps:
        if m.start <= addr < m.end:
            return f"0x{addr:X}  {m.name or 'anon'} [{prot_text(m.prot)}]"
    return ""


def is_exec(maps, addr: int) -> bool:
    return any(m.start <= addr < m.end and (m.prot & 4) for m in maps)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("interrupt channel closed")
        buf.extend(chunk)
    return bytes(buf)


class InterruptListener:
    """Listens on TCP 755; the console connects here after CMD_DEBUG_ATTACH."""

    def __init__(
        self,
        on_event: Callable[[StopEvent], None],
        on_log: Callable[[str], None],
        port: int = INTERRUPT_PORT,
        on_closed: Optional[Callable[[], None]] = None,
    ) -> None:
        self.on_event = on_event
        self.on_log = on_log
        self.on_closed = on_closed   # the console dropped the debug channel (not a local stop())
        self.port = port
        self._srv: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._waiter: Optional[queue.Queue] = None
        self.connected = False

    # -- lifecycle ----------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", self.port))
        except OSError as exc:
            srv.close()
            raise RuntimeError(
                f"cannot listen on port {self.port} for debugger events: {exc}. "
                "Close any other debugger/ps5debug client that uses port 755"
                + (" (on Linux/macOS ports below 1024 need root)." if self.port < 1024 else ".")
            ) from exc
        srv.listen(1)
        srv.settimeout(0.5)
        self._srv = srv
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        srv, self._srv = self._srv, None
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        self.connected = False

    # -- event delivery -----------------------------------------------
    def arm_waiter(self) -> queue.Queue:
        """The next stop event goes to the returned queue instead of on_event."""
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._waiter = q
        return q

    def disarm_waiter(self) -> None:
        with self._lock:
            self._waiter = None

    def _deliver(self, evt: StopEvent) -> None:
        with self._lock:
            w, self._waiter = self._waiter, None
        if w is not None:
            w.put(evt)
        else:
            self.on_event(evt)

    # -- thread -------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            srv = self._srv
            if srv is None:
                return
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(None)
            self.connected = True
            self.on_log(f"debugger channel connected from {addr[0]}:{addr[1]}")
            try:
                while not self._stop.is_set():
                    self._deliver(parse_event(_recv_exact(conn, PACKET_SIZE)))
            except (ConnectionError, OSError):
                if not self._stop.is_set():
                    self.on_log("debugger channel closed")
                    if self.on_closed:
                        self.on_closed()
            finally:
                self.connected = False
                try:
                    conn.close()
                except OSError:
                    pass
