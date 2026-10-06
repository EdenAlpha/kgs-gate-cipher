#!/usr/bin/env python3
"""Minimal MessagePack encoder, for the `req` field under PACK_MODE_MSGPACK.

`CommandRequest.req` is a `string`, and `packMode` selects the encoding:
`PACK_MODE_JSON = 0`, `PACK_MODE_MSGPACK = 1`. Everything sent so far has been
JSON, because a JSON body is at least well-formed and the server validates that.
But the game's payloads are almost certainly msgpack -- the enum exists, and
msgpack is what a compact binary protocol over a string field would use.

The encoder covers what a command envelope needs: nil, bool, ints, floats,
str, bin, arrays and maps, with the shortest-form encoding msgpack specifies.
No dependency, so it runs anywhere.
"""
from __future__ import annotations

import struct


def enc_nil() -> bytes:
    return b"\xc0"


def enc_bool(v: bool) -> bytes:
    return b"\xc3" if v else b"\xc2"


def enc_int(v: int) -> bytes:
    if 0 <= v <= 0x7F:
        return struct.pack("B", v)
    if -32 <= v < 0:
        return struct.pack("b", v)
    if 0 <= v <= 0xFF:
        return b"\xcc" + struct.pack("B", v)
    if 0 <= v <= 0xFFFF:
        return b"\xcd" + struct.pack(">H", v)
    if 0 <= v <= 0xFFFFFFFF:
        return b"\xce" + struct.pack(">I", v)
    if 0 <= v <= 0xFFFFFFFFFFFFFFFF:
        return b"\xcf" + struct.pack(">Q", v)
    if -0x80 <= v:
        return b"\xd0" + struct.pack("b", v)
    if -0x8000 <= v:
        return b"\xd1" + struct.pack(">h", v)
    if -0x80000000 <= v:
        return b"\xd2" + struct.pack(">i", v)
    return b"\xd3" + struct.pack(">q", v)


def enc_float(v: float) -> bytes:
    return b"\xcb" + struct.pack(">d", v)


def enc_str(s: str) -> bytes:
    b = s.encode("utf-8")
    n = len(b)
    if n < 32:
        return struct.pack("B", 0xA0 | n) + b
    if n <= 0xFF:
        return b"\xd9" + struct.pack("B", n) + b
    if n <= 0xFFFF:
        return b"\xda" + struct.pack(">H", n) + b
    return b"\xdb" + struct.pack(">I", n) + b


def enc_bin(b: bytes) -> bytes:
    n = len(b)
    if n <= 0xFF:
        return b"\xc4" + struct.pack("B", n) + b
    if n <= 0xFFFF:
        return b"\xc5" + struct.pack(">H", n) + b
    return b"\xc6" + struct.pack(">I", n) + b


def enc_array(items) -> bytes:
    n = len(items)
    if n < 16:
        head = struct.pack("B", 0x90 | n)
    elif n <= 0xFFFF:
        head = b"\xdc" + struct.pack(">H", n)
    else:
        head = b"\xdd" + struct.pack(">I", n)
    return head + b"".join(enc(v) for v in items)


def enc_map(d) -> bytes:
    items = list(d.items()) if hasattr(d, "items") else list(d)
    n = len(items)
    if n < 16:
        head = struct.pack("B", 0x80 | n)
    elif n <= 0xFFFF:
        head = b"\xde" + struct.pack(">H", n)
    else:
        head = b"\xdf" + struct.pack(">I", n)
    out = [head]
    for k, v in items:
        out.append(enc(k))
        out.append(enc(v))
    return b"".join(out)


def enc(v) -> bytes:
    if v is None:
        return enc_nil()
    if isinstance(v, bool):
        return enc_bool(v)
    if isinstance(v, int):
        return enc_int(v)
    if isinstance(v, float):
        return enc_float(v)
    if isinstance(v, str):
        return enc_str(v)
    if isinstance(v, (bytes, bytearray)):
        return enc_bin(bytes(v))
    if isinstance(v, (list, tuple)):
        return enc_array(v)
    if isinstance(v, dict):
        return enc_map(v)
    raise TypeError("cannot msgpack %r" % type(v))


def decode(b: bytes, i: int = 0):
    """Decode one value; returns (value, next_offset). Used by the self-test."""
    c = b[i]
    if c <= 0x7F:
        return c, i + 1
    if c >= 0xE0:
        return c - 256, i + 1
    if 0x80 <= c <= 0x8F:
        return _map(b, i, c & 0x0F)
    if 0x90 <= c <= 0x9F:
        return _arr(b, i, c & 0x0F)
    if 0xA0 <= c <= 0xBF:
        n = c & 0x1F
        return b[i + 1:i + 1 + n].decode("utf-8", "replace"), i + 1 + n
    if c == 0xC0:
        return None, i + 1
    if c == 0xC2:
        return False, i + 1
    if c == 0xC3:
        return True, i + 1
    fmts = {0xC4: (1, "bin"), 0xC5: (2, "bin"), 0xC6: (4, "bin"),
            0xD9: (1, "str"), 0xDA: (2, "str"), 0xDB: (4, "str"),
            0xCC: (1, "uint"), 0xCD: (2, "uint"), 0xCE: (4, "uint"),
            0xCF: (8, "uint"), 0xD0: (1, "int"), 0xD1: (2, "int"),
            0xD2: (4, "int"), 0xD3: (8, "int")}
    if c in fmts:
        size, kind = fmts[c]
        n = int.from_bytes(b[i + 1:i + 1 + size], "big")
        raw = b[i + 1 + size:i + 1 + size + n]
        if kind == "str":
            return raw.decode("utf-8", "replace"), i + 1 + size + n
        if kind == "bin":
            return raw, i + 1 + size + n
        return (n if kind == "uint" else
                n - (1 << (size * 8)) if n >> (size * 8 - 1) else n), i + 1 + size
    if c == 0xCA:
        return struct.unpack_from(">f", b, i + 1)[0], i + 5
    if c == 0xCB:
        return struct.unpack_from(">d", b, i + 1)[0], i + 9
    if c in (0xD9, 0xDA, 0xDB):
        pass
    if c in (0xDC, 0xDD):
        size = 2 if c == 0xDC else 4
        return _arr(b, i, int.from_bytes(b[i + 1:i + 1 + size], "big"),
                    size + 1)
    if c in (0xDE, 0xDF):
        size = 2 if c == 0xDE else 4
        return _map(b, i, int.from_bytes(b[i + 1:i + 1 + size], "big"),
                    size + 1)
    raise ValueError("unhandled msgpack byte 0x%02x at %d" % (c, i))


def _arr(b, i, n, off=1):
    i += off
    out = []
    for _ in range(n):
        v, i = decode(b, i)
        out.append(v)
    return out, i


def _map(b, i, n, off=1):
    i += off
    out = {}
    for _ in range(n):
        k, i = decode(b, i)
        v, i = decode(b, i)
        out[k] = v
    return out, i


CASES = [
    (None, b"\xc0"),
    (True, b"\xc3"),
    (False, b"\xc2"),
    (0, b"\x00"),
    (127, b"\x7f"),
    (128, b"\xcc\x80"),
    (256, b"\xcd\x01\x00"),
    (65536, b"\xce\x00\x01\x00\x00"),
    (-1, b"\xff"),
    (-33, b"\xd0\xdf"),
    (1.5, b"\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00"),
    ("", b"\xa0"),
    ("abc", b"\xa3abc"),
    (b"\x01\x02", b"\xc4\x02\x01\x02"),
    ([1, 2, 3], b"\x93\x01\x02\x03"),
    ({}, b"\x80"),
    ({"a": 1}, b"\x81\xa1a\x01"),
    ({"a": 1, "b": [True, None]}, b"\x82\xa1a\x01\xa1b\x92\xc3\xc0"),
]


def main() -> int:
    ok = True
    for v, want in CASES:
        got = enc(v)
        flag = "ok " if got == want else "BAD"
        if got != want:
            ok = False
        back, _ = decode(got) if got else (None, 0)
        rt = "ok " if back == v else "BAD"
        if back != v:
            ok = False
        print("%s enc  %-22r -> %-24s  %s roundtrip %r"
              % (flag, v, got.hex(), rt, back))
    print("\nMSGPACK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
