#!/usr/bin/env python3
"""VA -> file offset via ELF PHDRs, then qword-dump with string resolution.

    python va_read.py 0xa4b0140 0xa4b01a0
"""
from __future__ import annotations

import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")


def segs(d: bytes):
    e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
    e_phnum = struct.unpack_from("<H", d, 0x38)[0]
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        t, fl = struct.unpack_from("<II", d, o)
        po, pv, _, pf, _, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        if t == 1:
            out.append((pv, po, pf))
    return out


def va2off(segs, va: int):
    for pv, po, pf in segs:
        if pv <= va < pv + pf:
            return va - pv + po
    return None


def cstr(d: bytes, va: int, segs) -> str:
    off = va2off(segs, va)
    if off is None:
        return ""
    raw = d[off:off + 72].split(b"\x00")[0]
    if raw and all(32 <= b < 127 for b in raw):
        return raw.decode()
    return ""


def main() -> int:
    d = open(SO, "rb").read()
    sg = segs(d)
    lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
    for va in range(lo & ~7, hi, 8):
        off = va2off(sg, va)
        if off is None or off + 8 > len(d):
            print("  %#x -> (unmapped)" % va)
            continue
        (v,) = struct.unpack_from("<Q", d, off)
        print("  %#x -> %#014x  %r" % (va, v, cstr(d, v, sg)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
