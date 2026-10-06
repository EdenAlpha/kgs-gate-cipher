#!/usr/bin/env python3
"""Find every reference (load AND store) to the task-provider global
0xa4b2648 and its neighbours 0xa4b2000 / 0xa4b2010 / 0xa4b2028 / 0xa4b2038.
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

PAGES = {0xA4B2000, 0xA4B2648 & ~0xFFF, 0xA4B3000, 0xA4B1000}


def imm_hi(i):
    v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
    if v & (1 << 20):
        v -= 1 << 21
    return v << 12


def imm12(i):
    return (i >> 10) & 0xFFF


def page_ok(a):
    return any(a & ~0xFFF == p for p in PAGES)


def main():
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)

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
        # STR xt,[xn,#imm]
        if (i & 0xFFC00000) == 0xF9000000 and last[0] == rn:
            a = last[1] + imm12(i) * 8
            if page_ok(a):
                hits[a].append((pc, "STR"))
        # LDR xt,[xn,#imm]
        if (i & 0xFFC00000) == 0xF9400000 and last[0] == rn:
            a = last[1] + imm12(i) * 8
            if page_ok(a):
                hits[a].append((pc, "LDR"))
        # ADD imm
        if (i & 0xFFC00000) == 0x91000000 and last[0] == rn:
            a = last[1] + imm12(i)
            if page_ok(a):
                hits[a].append((pc, "ADD"))

    for a, sites in sorted(hits.items()):
        stores = [s for s in sites if s[1] == "STR"]
        print(f"\n{a}: {len(sites)} ref(s), {len(stores)} STORE(s)")
        for s, k in sites[:14]:
            print(f"    {s:#x}  {k}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
