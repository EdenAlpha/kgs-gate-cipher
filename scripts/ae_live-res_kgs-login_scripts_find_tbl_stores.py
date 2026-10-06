#!/usr/bin/env python3
"""Show ONLY the stores to 0xA4CF018 (the online command table) and the
functions they live in."""
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
TARGET = 0xA4CF018


def imm_hi(i):
    v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
    if v & (1 << 20):
        v -= 1 << 21
    return v << 12


def imm12(i):
    return (i >> 10) & 0xFFF


def main():
    # FDE ranges
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

    last = (None, None)
    print(f"stores to {TARGET:#x}:")
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        pc = TEXT_VADDR + idx * 4
        if (i & 0x80000000) and (i & 0x1F000000) == 0x10000000:
            last = (i & 0x1F, (pc & ~0xFFF) + imm_hi(i))
            continue
        if (i & 0x80000000) == 0 and (i & 0x1F000000) == 0x10000000:
            continue
        rn = (i >> 5) & 0x1F
        if (i & 0xFFC00000) == 0xF9000000 and last[0] == rn:
            a = last[1] + imm12(i) * 8
            if a == TARGET:
                e = enclosing(pc)
                print(f"  {pc:#x}  in fn {e[0]:#x} (size {e[1]-e[0]:#x})"
                      if e else f"  {pc:#x}")
        if (i & 0xFFC00000) == 0xA9000000 and last[0] == rn:
            a = last[1] + imm12(i) * 8
            if a == TARGET:
                e = enclosing(pc)
                print(f"  {pc:#x}  STP in fn {e[0]:#x}"
                      if e else f"  {pc:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
