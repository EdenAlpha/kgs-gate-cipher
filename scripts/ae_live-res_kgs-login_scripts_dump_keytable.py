#!/usr/bin/env python3
"""Dump a MessagePack key table (array of pointers to C strings).

    python dump_keytable.py 0x97e3000 0x97e3c00

Used to read the per-command field tables the ctor writer materialises
(e.g. CMD_CREATEJOIN_ROOM: 0x97e3bd0 / 0x97e3048).
"""
from __future__ import annotations

import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")


def cstr(d: bytes, off: int) -> str:
    end = d.find(b"\x00", off)
    return d[off:end].decode("latin1", "replace") if 0 <= off < len(d) else ""


def main() -> int:
    d = open(SO, "rb").read()
    lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
    for off in range(lo & ~7, hi, 8):
        (v,) = struct.unpack_from("<Q", d, off)
        if 0x400000 <= v < 0xA000000:
            s = cstr(d, v)
            if s and s.isprintable() and len(s) > 1:
                print("  %#x -> %#x  %r" % (off, v, s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
