#!/usr/bin/env python3
"""Find the enclosing functions of the stores to 0xa4cf018 and show them."""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

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

    reg = {}
    sites = []
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        pc = TEXT_VADDR + idx * 4
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
            if a == TARGET:
                sites.append(pc)

    print(f"stores to {TARGET:#x}: {len(sites)}")
    fns = {}
    for pc in sites:
        e = enclosing(pc)
        fn = e[0] if e else None
        fns.setdefault(fn, []).append(pc)
    for fn, pcs in sorted(fns.items(), key=lambda kv: (kv[0] or 0)):
        print(f"\n  fn {fn:#x}: {len(pcs)} store(s)")
        for pc in pcs[:6]:
            print(f"      {pc:#x}")

    # disassemble the most promising (the one with the most stores)
    best = max(fns.items(), key=lambda kv: len(kv[1]))
    fn = best[0]
    if fn is None:
        return 0
    print("\n" + "=" * 74)
    print(f"disassembling {fn:#x} (the busiest writer)")
    print("=" * 74)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    e = enclosing(fn + 4)
    size = (e[1] - e[0]) if e else 0x400
    with open(SO, "rb") as f:
        f.seek(fn - 0x4000)
        code = f.read(min(size, 0x800))
    n = 0
    for ins in md.disasm(code, fn):
        mark = "  <==" if ins.address in best[1] else ""
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}{mark}")
        n += 1
        if n > 90:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
