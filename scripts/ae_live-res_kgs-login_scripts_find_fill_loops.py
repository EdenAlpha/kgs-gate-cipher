#!/usr/bin/env python3
"""Find the startup code that materialises vtable slots.

The binary ships with .init_array and vtable slots zeroed; Android's loader
fills the ones whose addend is the load base.  For vtables that cannot be
enough (base+0 is not a function address), so the application must write them
during startup.

This hunts for the writer by looking for the idiom that fills a vtable:
    adrp  xD, <page of the table>
    add   xD, xD, #<off>
    ... loop over slots ...
    adrp  xN, <text page>      ; the target function
    add   xN, xN, #<off>
    str   xN, [xD, ...]        ; into successive 8-byte slots
    add   xD, xD, #8
    cmp/branch
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
VT = 0x97A2600

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


def insn(a):
    o = TEXT_OFF + (a - TEXT_V)
    return struct.unpack_from("<I", data, o)[0] if 0 <= o <= len(data) - 4 else 0


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
    """Find loops that str 8-byte values into a table, i.e. vtable builders.

    Scan for `str xN, [xM, #imm]` where the stored register was recently
    materialised by adrp/add into .text.  Those are the fill loops.
    """
    print("=== scanning for vtable fill loops (str of an adrp-built value) ===")
    hits = []
    n_ins = TEXT_SIZE // 4
    recent = {}                       # reg -> (addr, value) for adrp+add
    for i in range(n_ins):
        a = TEXT_V + i * 4
        w = insn(a)
        ad = adrp_target(w, a)
        if ad is None:
            continue
        rd = w & 0x1F
        nxt = insn(a + 4)
        if (nxt & 0xFFC003E0) == 0x91000000 and ((nxt >> 5) & 0x1F) == rd:
            i2 = (nxt >> 10) & 0xFFF
            if (nxt >> 22) & 1:
                i2 <<= 12
            val = ad + i2
            if TEXT_LO <= val < TEXT_HI:
                recent[rd] = (a, val)
                # look ahead a few instructions for a store of this reg
                for k in range(1, 7):
                    w2 = insn(a + 4 * k)
                    if (w2 & 0xFFC003FF) == 0xF9000000:
                        rt = w2 & 0x1F
                        if rt == rd:
                            s, e = fn_of(a)
                            hits.append((a, val, rt, s, e))
                        break
        if len(recent) > 24:
            recent.clear()

    print(f"candidate fill stores: {len(hits)}")
    for a, val, rt, s, e in hits[:40]:
        print(f"   {a:#x}  -> {val:#x}  fn {s:#x}..{e:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
