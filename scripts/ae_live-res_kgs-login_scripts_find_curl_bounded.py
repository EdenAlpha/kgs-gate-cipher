#!/usr/bin/env python3
"""Scan a region for BL to curl_easy_setopt, bounded to real function extents
(from funcs_eh.txt) so neighbouring functions don't create false positives."""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

CURL = 0x6886498
LO, HI = 0x7D03B00, 0x7D05000

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


def main():
    with open(SO, "rb") as f:
        f.seek(LO - 0x4000)
        text = f.read(HI - LO)

    found = []
    for i in range(len(text) // 4):
        w = struct.unpack_from("<I", text, i * 4)[0]
        if (w & 0xFC000000) == 0x94000000:
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            t = (LO + i * 4) + (imm << 2)
            if t == CURL:
                found.append(LO + i * 4)

    print(f"BL to curl_easy_setopt in {LO:#x}..{HI:#x}: {len(found)}")
    for pc in found:
        e = enclosing(pc)
        if e:
            print(f"  {pc:#x}  in fn {e[0]:#x} (size {e[1]-e[0]:#x})")
        else:
            print(f"  {pc:#x}  (no FDE)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
