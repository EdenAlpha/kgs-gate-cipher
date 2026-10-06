#!/usr/bin/env python3
"""Disassemble around the two writers of the session global 0xa4ab6a8."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
FDE = os.path.join(HERE, "funcs_eh.txt")

SITES = [0x7CDA1B0, 0x7CDA224]


def enclosing(addr):
    lo, hi = 0, 544638
    best = None
    arr = []
    with open(FDE, encoding="utf-8") as f:
        for line in f:
            p = line.split()
            arr.append((int(p[0], 16), int(p[1], 16)))
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
                print(f"site {a:#x} is inside function {e[0]:#x} "
                      f"(size {e[1]-e[0]:#x})")
                start = e[0]
            else:
                print(f"site {a:#x}: NOT in any FDE; using {a:#x}")
                start = a - 0x80
            print("=" * 74)
            f.seek(start - 0x4000)
            code = f.read(0x200)
            n = 0
            for ins in md.disasm(code, start):
                mark = "  <== WRITES session" if ins.address == a else ""
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}{mark}")
                n += 1
                if n > 60:
                    break
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
