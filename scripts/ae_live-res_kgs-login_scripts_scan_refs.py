#!/usr/bin/env python3
"""One pass over .text; report every ADRP(+ADD / +ADD+LDR) that materialises
one of the given addresses.

    python scan_refs.py 0xADDR [0xADDR ...]
"""
from __future__ import annotations

import bisect
import re
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(SO, "rb").read()
starts, recs = [], []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if m:
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        starts.append(s)
        recs.append((s, e))


def fn_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return recs[i] if i >= 0 and starts[i] <= a < recs[i][1] else (0, 0)


def main() -> int:
    targets = {int(a, 16) for a in sys.argv[1:]}
    if not targets:
        print("no targets")
        return 1
    end = TEXT_OFF + TEXT_SIZE
    hits = []
    for p in range(TEXT_OFF, end, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if (w & 0x9F000000) != 0x90000000:          # ADRP
            continue
        pc = TEXT_V + (p - TEXT_OFF)
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= 1 << 33
        page = (pc & ~0xFFF) + imm
        rn = (w >> 5) & 31
        w2 = struct.unpack_from("<I", data, p + 4)[0]
        if (w2 & 0xFFC00000) != 0x91000000:          # ADD (immediate) 64-bit
            continue
        if ((w2 >> 5) & 31) != rn:
            continue
        i2 = (w2 >> 10) & 0xFFF
        if (w2 >> 22) & 1:
            i2 <<= 12
        t = page + i2
        if t in targets:
            kind = "ADD"
            w3 = struct.unpack_from("<I", data, p + 8)[0] if p + 12 <= end else 0
            if (w3 & 0xFFC00000) == 0xF9400000 and ((w3 >> 5) & 31) == (w2 & 31):
                t2 = t + ((w3 >> 10) & 0xFFF) * 8
                if t2 in targets:
                    kind, t = "LDR", t2
            s, e = fn_of(pc)
            hits.append((pc, kind, t, s, e))
    for pc, kind, t, s, e in hits:
        print(f"  {pc:#x} {kind} -> {t:#x}   fn {s:#x}..{e:#x}")
    print(f"total {len(hits)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
