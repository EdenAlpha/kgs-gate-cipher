#!/usr/bin/env python3
"""Correctly track ADRP+ADD chains and find the REAL writer of the online
command table 0xa4cf018 (and its neighbours)."""
from __future__ import annotations

import os
import struct
import sys

from elftools.elf.elffile import ELFFile

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

PAGES = {0xA4CF000, 0xA4CE000, 0xA4D0000, 0xA4CC000,
         0xA4CB000, 0xA4CD000}


def imm_hi(i):
    v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
    if v & (1 << 20):
        v -= 1 << 21
    return v << 12


def imm12(i):
    return (i >> 10) & 0xFFF


def main():
    arr = []
    with open(os.path.join(HERE, "funcs_eh.txt"), encoding="utf-8") as f:
        for line in f:
            p = line.split()
            arr.append((int(p[0], 16), int(p[1], 16)))

    def enclosing(addr):
        lo, hi = 0, len(arr) - 1
        best = None
        while lo <= hi:
            m = (lo + hi) // 2
            if arr[m][0] <= addr:
                best = m
                lo = m + 1
            else:
                hi = m - 1
        if best is None:
            return None
        a, b = arr[best]
        return (a, b) if a <= addr < b else None

    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)

    # last: reg -> resolved address (ADRP page, or ADD result)
    reg = {}
    stores = []
    loads = []
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        pc = TEXT_VADDR + idx * 4
        if (i & 0x80000000) and (i & 0x1F000000) == 0x10000000:  # ADRP
            reg[i & 0x1F] = (pc & ~0xFFF) + imm_hi(i)
            continue
        if (i & 0x80000000) == 0 and (i & 0x1F000000) == 0x10000000:
            continue
        rn = (i >> 5) & 0x1F
        rd = i & 0x1F
        # ADD imm
        if (i & 0xFFC00000) == 0x91000000 and rn in reg:
            a = reg[rn] + imm12(i)
            reg[rd] = a
            continue
        # STR xt,[xn,#imm]
        if (i & 0xFFC00000) == 0xF9000000 and rn in reg:
            a = reg[rn] + imm12(i) * 8
            if (a & ~0xFFF) in PAGES:
                stores.append((pc, a))
        # LDR xt,[xn,#imm]
        if (i & 0xFFC00000) == 0xF9400000 and rn in reg:
            a = reg[rn] + imm12(i) * 8
            if (a & ~0xFFF) in PAGES:
                loads.append((pc, a))

    # group stores by address
    by_addr = {}
    for pc, a in stores:
        by_addr.setdefault(a, []).append(pc)

    print("STORES into the 0xa4cf000 region:")
    print("=" * 74)
    for a in sorted(by_addr):
        if not (0xA4CF000 <= a < 0xA4D0000):
            continue
        pcs = by_addr[a]
        fns = []
        for pc in pcs[:4]:
            e = enclosing(pc)
            fns.append(f"{e[0]:#x}" if e else "?")
        print(f"  {a:#x}: {len(pcs)} store(s)  e.g. {', '.join(fns)}")

    print("\n" + "=" * 74)
    print(f"total: {len(stores)} stores, {len(loads)} loads")
    return 0


if __name__ == "__main__":
    sys.exit(main())
