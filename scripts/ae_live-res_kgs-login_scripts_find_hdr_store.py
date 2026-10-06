#!/usr/bin/env python3
"""Which function stores the curl header list at subreq+0x10070?

subreq+0x10070 is reached as  add xD, x?, #0x10, lsl #12 ; str xT, [xD, #0x70]
so we look for functions that contain both instructions.
"""
from __future__ import annotations

import bisect
import re
import struct

SO = r"apk_lab\libUE4.so"
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


def insn(a: int) -> int:
    o = TEXT_OFF + (a - TEXT_V)
    if o < 0 or o + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, o)[0]


# collect, per function, the set of registers made = base+0x10000, and stores
found = []
for si, (s, e) in enumerate(recs):
    if not (0x7c00000 <= s < 0x7f00000):        # only the game's own code
        continue
    plus = set()
    for a in range(s, e, 4):
        w = insn(a)
        if (w & 0xFFE003FF) == 0x91400008:      # add x8, xN, #0x10, lsl #12
            plus.add(8)
        elif (w & 0xFFE003FF) == 0x91400000:    # any other rd
            plus.add(w & 0x1F)
        elif (w & 0xFFE00FFF) == 0xD1400000:    # add xD, xN, #0x10, lsl #48?
            plus.add(w & 0x1F)
    if not plus:
        continue
    for a in range(s, e, 4):
        w = insn(a)
        if (w & 0xFFC003E0) == 0xF9000000:      # str xT, [xRn, #imm12*8]
            rn = (w >> 5) & 0x1F
            imm = ((w >> 10) & 0xFFF) * 8
            if rn in plus and imm in (0x70, 0x68, 0x60, 0x48, 0x28):
                found.append((a, s, e, rn, imm))

print(f"functions inspected; stores found: {len(found)}")
for a, s, e, rn, imm in found:
    print(f"  {a:#x}  str [x{rn}, #{imm:#x}]   in fn {s:#x}..{e:#x}")
