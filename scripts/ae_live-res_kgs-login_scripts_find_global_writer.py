#!/usr/bin/env python3
"""Who writes the global at 0x98d5148?

The login body builder (0x767ec60) reads it to fetch lang/region/platform.
In the real app it is set during full startup, which we do not run, so it is
null and the code walks a garbage vtable chain.
"""
from __future__ import annotations

import bisect
import re
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(SO, "rb").read()

starts, recs = [], []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if m:
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        starts.append(s)
        recs.append((s, e))


def fn_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return recs[i] if i >= 0 and starts[i] <= a < recs[i][1] else (0, 0)


def insn(a: int) -> int:
    o = TEXT_OFF + (a - TEXT_V)
    if o < 0 or o + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, o)[0]


def scan(target_page: int, target_off: int, label: str) -> None:
    print(f"=== stores into {label} (page {target_page:#x} off {target_off:#x})")
    hits = []
    for p in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE, 4):
        w = insn(TEXT_V + (p - TEXT_OFF))
        if (w & 0x9F000000) != 0x90000000:
            continue
        pc = TEXT_V + (p - TEXT_OFF)
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= 1 << 33
        if (pc & ~0xFFF) + imm != target_page:
            continue
        rn = (w >> 5) & 31
        for k in range(1, 6):
            w2 = insn(pc + 4 * k)
            if ((w2 & 0xFFC003E0) == 0xF9000000
                    and ((w2 >> 5) & 31) == rn
                    and ((w2 >> 10) & 0xFFF) * 8 == target_off):
                s, e = fn_of(pc + 4 * k)
                hits.append((pc + 4 * k, s, e))
    for a, s, e in hits[:25]:
        print(f"   {a:#x}   fn {s:#x}..{e:#x}")
    print(f"   total {len(hits)}\n")


def main() -> int:
    scan(0x98D5000, 0x148, "0x98d5148")
    return 0


if __name__ == "__main__":
    sys.exit(main())
