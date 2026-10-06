#!/usr/bin/env python3
"""Raw qword dump of a data region (no filtering) so we can see whether the
per-command key tables hold pointers, offsets, or reloc addends.

    python dump_raw.py 0x97e3000 0x97e3c00
"""
from __future__ import annotations

import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")


def cstr(d: bytes, off: int) -> str:
    if 0 <= off < len(d):
        end = d.find(b"\x00", off, off + 80)
        s = d[off:end if end > off else off + 80]
        if s and all(32 <= b < 127 for b in s):
            return s.decode()
    return ""


def main() -> int:
    d = open(SO, "rb").read()
    lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
    for off in range(lo & ~7, hi, 8):
        (v,) = struct.unpack_from("<Q", d, off)
        s = cstr(d, v)
        raw = "".join(chr(b) if 32 <= b < 127 else "." for b in d[off:off + 8])
        print("  %#x  %016x  %-8s  %s" % (off, v, raw,
                                          ("-> %r" % s) if s else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
