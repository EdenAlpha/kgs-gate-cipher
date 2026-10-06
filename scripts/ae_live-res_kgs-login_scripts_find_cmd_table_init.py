#!/usr/bin/env python3
"""Find every reference to the 0xa4cf000 page (where the online command
table 0xa4cff18 lives).  That reveals what initializes it."""
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

PAGES = [0xA4CF000, 0xA4CE000, 0xA4D0000, 0xA4CC000, 0xA4CB000]


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
        if (i & 0x80000000) and (i & 0x1F000000) == 0x10000000:
            last = (i & 0x1F, (pc & ~0xFFF) + imm_hi(i))
            continue
        if (i & 0x80000000) == 0 and (i & 0x1F000000) == 0x10000000:
            continue
        rn = (i >> 5) & 0x1F
        if (i & 0xFFC00000) == 0xF9000000 and last[0] == rn:   # STR
            a = last[1] + imm12(i) * 8
            if (a & ~0xFFF) in want:
                hits[a].append((pc, "STR"))
        if (i & 0xFFC00000) == 0xF9400000 and last[0] == rn:   # LDR
            a = last[1] + imm12(i) * 8
            if (a & ~0xFFF) in want:
                hits[a].append((pc, "LDR"))
        if (i & 0xFFC00000) == 0x91000000 and last[0] == rn:   # ADD
            a = last[1] + imm12(i)
            if (a & ~0xFFF) in want:
                hits[a].append((pc, "ADD"))

    for a, sites in sorted(hits.items()):
        stores = [s for s in sites if s[1] == "STR"]
        print(f"\n{a}: {len(sites)} ref(s), {len(stores)} STORE(s)")
        for s, k in sites[:12]:
            print(f"    {s:#x}  {k}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
