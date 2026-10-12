"""Tiny pure-Python AES (128/192/256) CBC - only used to open and write .mc4 cheat
files (a few KB), so no extra package has to be installed.  Uses pycryptodome or
cryptography automatically when one of them is available."""

from __future__ import annotations

_SBOX = bytearray(256)
_INV = bytearray(256)


def _init() -> None:
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (((q << 1) | (q >> 7)) & 0xFF) ^ (((q << 2) | (q >> 6)) & 0xFF) \
            ^ (((q << 3) | (q >> 5)) & 0xFF) ^ (((q << 4) | (q >> 4)) & 0xFF) ^ 0x63
        _SBOX[p] = x
        _INV[x] = p
        if p == 1:
            break
    _SBOX[0] = 0x63
    _INV[0x63] = 0


_init()


def _xt(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


def _expand(key: bytes) -> list[list[int]]:
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xt(rcon)
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _decrypt_block(rk: list[list[int]], blk: bytes) -> bytes:
    nr = len(rk) - 1
    s = [blk[i] ^ rk[nr][i] for i in range(16)]
    for r in range(nr - 1, -1, -1):
        # inverse shift rows (column-major state)
        s = [s[((c - r_) % 4) * 4 + r_] for c in range(4) for r_ in range(4)]
        s = [_INV[b] for b in s]
        s = [s[i] ^ rk[r][i] for i in range(16)]
        if r:
            out = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                out += [_mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9),
                        _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13),
                        _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11),
                        _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)]
            s = out
    return bytes(s)


def _encrypt_block(rk: list[list[int]], blk: bytes) -> bytes:
    nr = len(rk) - 1
    s = [blk[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, nr + 1):
        s = [_SBOX[b] for b in s]
        s = [s[((c + r_) % 4) * 4 + r_] for c in range(4) for r_ in range(4)]   # shift rows
        if r != nr:
            out = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                out += [_mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3],
                        a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3],
                        a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3),
                        _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)]
            s = out
        s = [s[i] ^ rk[r][i] for i in range(16)]
    return bytes(s)


def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """`data` must already be padded to 16 bytes."""
    if len(data) % 16:
        raise ValueError("data must be a multiple of 16 bytes (pad it first)")
    try:
        from Crypto.Cipher import AES  # type: ignore
        return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return e.update(data) + e.finalize()
    except ImportError:
        pass
    rk = _expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        prev = _encrypt_block(rk, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out += prev
    return bytes(out)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        data = data[: len(data) - len(data) % 16]
    try:
        from Crypto.Cipher import AES  # type: ignore
        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(data) + d.finalize()
    except ImportError:
        pass
    rk = _expand(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(rk, blk), prev))
        prev = blk
    return bytes(out)
