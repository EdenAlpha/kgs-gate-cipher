#!/usr/bin/env python3
"""Find code that takes the address of a given rodata literal.

  python xref_lit.py 0xbef163 [0x...]
"""
from __future__ import annotations

import bisect
import re
import struct
import sys

PATH = r"apk_lab\libUE4.so"
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(PATH, "rb").read()

starts = []
recs = []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if not m:
        continue
    starts.append(int(m.group(1), 16))
    recs.append((int(m.group(1), 16), int(m.group(2), 16)))


def insn(a):
    off = TEXT_OFF + (a - TEXT_V)
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def adrp(w, a):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (w & 31, (a & ~0xFFF) + (imm << 12))


def add_imm(w):
    if (w & 0xFFC00000) != 0x91000000:
        return None
    return (w & 31), ((w >> 5) & 31), ((w >> 10) & 0xFFF)


def scan(target: int, label: str) -> None:
    hits = []
    for a in range(TEXT_V, TEXT_V + TEXT_SIZE, 4):
        r = adrp(insn(a), a)
        if not r:
            continue
        rd, pg = r
        if (pg & ~0xFFF) != (target & ~0xFFF):
            continue
        for k in range(1, 8):
            ai = add_imm(insn(a + k * 4))
            if ai and ai[1] == rd:
                if pg + ai[2] == target:
                    i = bisect.bisect_right(starts, a) - 1
                    fn = recs[i][0] if i >= 0 and starts[i] <= a < recs[i][1] else 0
                    hits.append((fn, a, recs[i][1]))
                break
    print(f"=== {label} {target:#x}  ({len(hits)} hits) ===")
    for fn, a, end in hits:
        print(f"    insn {a:#x}   fn {fn:#x}..{end:#x} size {end - fn:#x}")


for arg in sys.argv[1:]:
    scan(int(arg, 16), "xref")
