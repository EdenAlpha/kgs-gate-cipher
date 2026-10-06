#!/usr/bin/env python3
"""Find who materialises vtable 0x97a2600 (and how many vtables exist).

BUG FIXED: earlier scans built the address as TEXT_V + p - TEXT_OFF while p
was ALREADY a file offset, so every lookup was out by 0x4000 and every result
came back empty.  Correct form:  addr = TEXT_V + (p - TEXT_OFF).
"""
from __future__ import annotations

import bisect
import re
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48
TEXT_LO, TEXT_HI = 0x28293C0, 0x8B75140

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


def word_at_vaddr(a: int) -> int:
    o = TEXT_OFF + (a - TEXT_V)
    if o < 0 or o + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, o)[0]


def adrp_target(w, pc):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= 1 << 33
    return (pc & ~0xFFF) + imm


def main() -> int:
    # ---- 1. count vtables across the whole image, properly this time ----
    print("=== vtable census (whole image) ===")
    runs = 0
    tables = []
    for p in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE, 4):
        a = TEXT_V + (p - TEXT_OFF)
        w = word_at_vaddr(a)
        nxt = word_at_vaddr(a + 4)
        if (nxt & 0xFFC003E0) == 0x91000000 and ((nxt >> 5) & 0x1F) == \
                (word_at_vaddr(a + 4) & 0x1F) and \
                (word_at_vaddr(a + 4) & 0xFFC00000) == 0x91000000:
            rn = (word_at_vaddr(a + 4) >> 5) & 0x1F
            rd = w & 0x1F
            ad = adrp_target(word_at_vaddr(a - 4), a - 4)
            if ad is None or rn != rd:
                continue
            i2 = (word_at_vaddr(a + 4) >> 10) & 0xFFF
            if (word_at_vaddr(a + 4) >> 22) & 1:
                i2 <<= 12
            val = ad + i2
            if TEXT_LO <= val < TEXT_HI:
                runs += 1
                if runs <= 25:
                    s, e = fn_of(a - 4)
                    print(f"   {a-4:#x} -> {val:#x}  (fn {s:#x}..{e:#x})")
    print(f"   adrp+add -> text-pointer sites: {runs}")

    # ---- 2. the specific ctor, verified ---------------------------------
    print(f"\n=== verify the known ctor at 0x767eaf0 ===")
    for a in range(0x767EB00, 0x767EB14, 4):
        w = word_at_vaddr(a)
        print(f"   {a:#x}: {w:#010x}")
    ad = adrp_target(word_at_vaddr(0x767EB04), 0x767EB04)
    add = word_at_vaddr(0x767EB08)
    imm = (add >> 10) & 0xFFF
    print(f"   -> vtable = {(ad or 0) + imm:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
