#!/usr/bin/env python3
"""Find code that loads from a given struct-field offset.

  python find_field.py 0x138 0x170

Only reports loads whose base register is a callee-saved / argument register
(x0..x28), never SP -- SP offsets are just stack slots and drown the result.
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

starts, recs = [], []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if not m:
        continue
    s, e = int(m.group(1), 16), int(m.group(2), 16)
    starts.append(s)
    recs.append((s, e))


def insn(a):
    off = TEXT_OFF + (a - TEXT_V)
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def decode(w):
    """-> (base_reg, offset) if this is a load with an immediate offset."""
    base, off = None, None
    op = w >> 22
    if (w & 0xFFC00000) == 0xF9400000:            # LDR X, [Xn, #imm*8]
        base, off = w & 31, ((w >> 10) & 0xFFF) * 8
    elif (w & 0xFFC00000) == 0xB9400000:          # LDR W, [Xn, #imm*4]
        base, off = w & 31, ((w >> 10) & 0xFFF) * 4
    elif (w & 0xFFC00000) in (0x39400000,         # LDRB
                              0x79400000,         # LDRH
                              0xB9400000):
        base, off = w & 31, ((w >> 10) & 0xFFF)
    elif (w & 0xFFE00C00) == 0x38400C00:          # LDRSB
        base, off = w & 31, ((w >> 12) & 0x1FF)
    elif (w & 0xFFE00C00) == 0x78400C00:          # LDRSH
        base, off = w & 31, ((w >> 12) & 0x1FF)
    elif (w & 0xFFE00C00) == 0xF8400C00:          # LDRSW / LDUR X
        base, off = w & 31, ((w >> 12) & 0x1FF)
    elif (w & 0xFFE00C00) == 0xB8400C00:          # LDUR W
        base, off = w & 31, ((w >> 12) & 0x1FF)
    else:
        return None
    if off >= 0x100:
        off -= 0x200                              # signed imm9 forms
    if off < 0:
        return None
    return base, off, op


def scan(target: int) -> None:
    hits = {}
    for a in range(TEXT_V, TEXT_V + TEXT_SIZE, 4):
        r = decode(insn(a))
        if not r:
            continue
        base, off, _ = r
        if off != target or base > 28:            # skip SP(31) and XZR
            continue
        i = bisect.bisect_right(starts, a) - 1
        fn = recs[i][0] if i >= 0 and starts[i] <= a < recs[i][1] else 0
        hits.setdefault(fn, []).append(a)
    print(f"=== field {target:#x}: {len(hits)} functions ===")
    for fn in sorted(hits):
        addrs = hits[fn]
        i = bisect.bisect_right(starts, fn)
        end = recs[i - 1][1] if i > 0 else fn
        print(f"  fn {fn:#x}..{end:#x}  {len(addrs):3d} hits   "
              f"first {addrs[0]:#x}")
        if len(addrs) <= 6:
            for a in addrs:
                print(f"        {a:#x}")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        scan(int(arg, 16))
