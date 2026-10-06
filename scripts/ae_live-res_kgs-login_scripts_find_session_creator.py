#!/usr/bin/env python3
"""Find every code site that references the 0xa4ab000 page (where the
session global 0xa4ab6a8 lives).  That tells us who creates the session.
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

PAGES = [0xA4AB000, 0xA4AC000, 0xA4A9000, 0xA4AA000, 0xA4AD000]


def imm_hi(i):
    v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
    if v & (1 << 20):
        v -= 1 << 21
    return v << 12


def imm12(i):
    return (i >> 10) & 0xFFF


def main():
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)

    want = set(PAGES)
    hits = defaultdict(list)
    last = (None, None)
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        pc = TEXT_VADDR + idx * 4
        # ADRP: bit31=1, bits[28:24]=10000  (immlo is bits[30:29], any value)
        if (i & 0x80000000) and (i & 0x1F000000) == 0x10000000:
            last = (i & 0x1F, (pc & ~0xFFF) + imm_hi(i))
            continue
        # ADR: bit31=0, bits[28:24]=10000
        if (i & 0x80000000) == 0 and (i & 0x1F000000) == 0x10000000:
            v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
            if v & (1 << 20):
                v -= 1 << 21
            a = pc + v
            if a in want:
                hits[a].append((pc, "ADR"))
            continue
        if (i & 0xFFC00000) == 0x91000000:          # ADD imm (unsigned)
            rn = (i >> 5) & 0x1F
            if last[0] == rn:
                a = last[1] + imm12(i)
                if (a & ~0xFFF) in want:
                    hits[a].append((pc, "ADRP+ADD"))
        # LDR xt, [xn, #imm] (unsigned offset, 64-bit) -> 0xF9400000
        if (i & 0xFFC00000) == 0xF9400000:
            rn = (i >> 5) & 0x1F
            if last[0] == rn:
                a = last[1] + (imm12(i) * 8)
                if (a & ~0xFFF) in want:
                    hits[a].append((pc, "ADRP+LDR"))

    for a, sites in sorted(hits.items()):
        print(f"\n{a:#x}  ({len(sites)} refs)")
        for s, k in sites[:14]:
            print(f"    {s:#x}  {k}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
