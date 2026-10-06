#!/usr/bin/env python3
"""Recover the vtable for the CMD_GET_SERVER_ENV class.

The vtable slots are zero in the file, so the values must come from the
linker's RELATIVE relocations, which are absent.  But every slot's value is
the address of a function in the same class, and every virtual call site in
the code does:

    ldr  xN, [x0]          ; vtable
    ldr  xF, [xN, #slot]   ; slot*8
    blr  xF

so we can enumerate the class's virtual functions by finding call sites whose
receiver is an object constructed by 0x767eaf0.  Simpler and sufficient:
the ctor stores the vtable pointer, and the *setter* of every field used by
the request pipeline lives in the same code neighbourhood.  Dump the region
0x767e000..0x7681000 as a function list -- those are the class's methods in
link order, which is vtable order.
"""
from __future__ import annotations

import re
import struct
import sys

from elftools.elf.elffile import ELFFile

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V, TEXT_OFF = 0x28293C0, 0x28253C0
VT = 0x97A2600

data = open(SO, "rb").read()
starts, recs = [], []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if m:
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        starts.append(s)
        recs.append((s, e))


def main() -> int:
    print("=== functions in the class neighbourhood (vtable order) ===")
    lo, hi = 0x767E000, 0x7681100
    idx = [i for i, (s, _) in enumerate(recs) if lo <= s < hi]
    for n, i in enumerate(idx):
        s, e = recs[i]
        mark = "   <-- ctor" if s == 0x767EAF0 else ""
        mark += "  <-- env-bind" if s == 0x767EC60 else ""
        mark += "  <-- env-serial" if s == 0x767EDBC else ""
        print(f"   [{n:2d}] {s:#x}..{e:#x}  len={e-s:#x}{mark}")

    # how many distinct vtable pages do all these ctors install?  If several
    # classes live here, their vtables are all zero too.
    print("\n=== all vtables installed by constructors in this region ===")
    lo_i, hi_i = max(0, idx[0]), min(len(recs) - 1, idx[-1])
    found = {}
    for s, e in recs[lo_i:hi_i + 1]:
        a = s
        while a < e:
            o = TEXT_OFF + (a - TEXT_V)
            if o < 0 or o + 4 > len(data):
                break
            x = struct.unpack_from("<I", data, o)[0]
            if (x & 0x9F000000) == 0x90000000:
                immlo = (x >> 29) & 3
                immhi = (x >> 5) & 0x7FFFF
                imm = ((immhi << 2) | immlo) << 12
                if imm & (1 << 32):
                    imm -= 1 << 33
                page = (a & ~0xFFF) + imm
                y = struct.unpack_from("<I", data, o + 4)[0]
                if (y & 0xFFC003E0) == 0x91000000 and ((y >> 5) & 0x1F) == (x & 0x1F):
                    i2 = (y >> 10) & 0xFFF
                    if (y >> 22) & 1:
                        i2 <<= 12
                    v = page + i2
                    if 0x8B75140 <= v < 0xA000000:
                        found.setdefault(v, []).append(a)
            a += 4
    for v, at in sorted(found.items()):
        print(f"   vtable {v:#x}  installed at {[hex(x) for x in at[:4]]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
