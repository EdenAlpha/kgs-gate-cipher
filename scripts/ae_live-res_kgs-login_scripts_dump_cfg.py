#!/usr/bin/env python3
"""Dump the endpoint-config table that get_endpoint_config (0x7d6532c) reads.

get_endpoint_config materialises literals in 0xa4b0000..0xa4b0218, and the
POST sender (0x7d04148) reads a function pointer out of 0xa4af000+0x18.  That
region is .data: file offset == VA, so the raw contents are the loaded values
(apart from relocations, whose addends are already virtual addresses).

Prints each 8-byte slot: as a pointer (with the C string it points at, if any)
and as raw ASCII, so hidden endpoint strings show up either way.
"""
from __future__ import annotations

import re
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

LO, HI = 0xA4AE800, 0xA4B0400


def main() -> int:
    d = open(SO, "rb").read()
    print("region %#x..%#x" % (LO, HI))
    for off in range(LO, HI, 8):
        if off + 8 > len(d):
            break
        (v,) = struct.unpack_from("<Q", d, off)
        # pointer into .text/.rodata?
        s = ""
        if 0x400000 <= v < 0xA000000:
            s = d[v:v + 96].split(b"\0")[0]
            try:
                s = s.decode("latin1")
            except Exception:
                s = repr(s)
        raw = d[off:off + 8]
        ascii_raw = "".join(chr(b) if 32 <= b < 127 else "."
                            for b in raw)
        interesting = isinstance(s, str) and s and s.isprintable() \
            and len(s) > 1
        if interesting or any(32 <= b < 127 for b in raw):
            print("  %#x  %#018x  %-8s  %s" % (
                off, v, ascii_raw, ("-> %r" % s) if interesting else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
