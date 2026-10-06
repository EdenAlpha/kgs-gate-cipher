#!/usr/bin/env python3
"""Disassemble the functions that register the task provider (0x7dbc104,
0x7dc4ae8) and the writer of 0xa4b2658 (0x7dc8d50)."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
FDE = os.path.join(HERE, "funcs_eh.txt")

SITES = [0x7DBC104, 0x7DC4AE8, 0x7DC8D50]


def enclosing(addr):
    arr = []
    with open(FDE, encoding="utf-8") as f:
        for line in f:
            p = line.split()
            arr.append((int(p[0], 16), int(p[1], 16)))
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


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for a in SITES:
            e = enclosing(a)
            print("=" * 74)
            if e:
                print(f"site {a:#x} in function {e[0]:#x} (size {e[1]-e[0]:#x})")
                start = e[0]
            else:
                print(f"site {a:#x}: not in an FDE; using {a-0x100:#x}")
                start = a - 0x100
            print("=" * 74)
            f.seek(start - 0x4000)
            code = f.read(0x300)
            n = 0
            for ins in md.disasm(code, start):
                mark = "  <==" if ins.address == a else ""
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}{mark}")
                n += 1
                if n > 70:
                    break
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
