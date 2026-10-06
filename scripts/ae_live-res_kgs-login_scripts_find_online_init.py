#!/usr/bin/env python3
"""The online module lives at 0x7dcxxxx.  Find its init: a function that
writes into the 0xa4cf000-0xa4d0000 .bss region (where the command table
0xa4cff18 lives)."""
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

LO, HI = 0x7DC0000, 0x7DE0000


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

    reg = {}
    hits = defaultdict(list)
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        pc = TEXT_VADDR + idx * 4
        if not (LO <= pc < HI):
            reg.clear()
            continue
        if (i & 0x80000000) and (i & 0x1F000000) == 0x10000000:
            reg[i & 0x1F] = (pc & ~0xFFF) + imm_hi(i)
            continue
        if (i & 0x80000000) == 0 and (i & 0x1F000000) == 0x10000000:
            continue
        rn = (i >> 5) & 0x1F
        rd = i & 0x1F
        if (i & 0xFFC00000) == 0x91000000 and rn in reg:
            reg[rd] = reg[rn] + imm12(i)
            continue
        if (i & 0xFFC00000) == 0xF9000000 and rn in reg:
            a = reg[rn] + imm12(i) * 8
            if 0xA4CF000 <= a < 0xA4D0000:
                hits[a].append(pc)

    print(f"stores into 0xa4cf000..0xa4d0000 from the online module:")
    for a in sorted(hits):
        print(f"  {a:#x}: {len(hits[a])}  e.g. {', '.join(hex(x) for x in hits[a][:3])}")
    if not hits:
        print("  (none found)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
