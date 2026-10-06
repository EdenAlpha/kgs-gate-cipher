#!/usr/bin/env python3
"""Verify the raw encoding of the instruction at 0x7cda454 and a few
other 'adrp #0xa4ab000' sites, to be sure our decoder agrees."""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

SITES = [0x7CDA454, 0x7CDA4CC, 0x7CDA544, 0x7CDA5D8, 0x7CDA798,
         0x7CDA814, 0x7CDA294, 0x7CDA3C4]


def decode(i):
    if (i & 0x80000000) and (i & 0x1F00000) == 0x100000:
        immlo = (i >> 29) & 3
        immhi = (i >> 5) & 0x7FFFF
        v = (immhi << 2) | immlo
        if v & (1 << 20):
            v -= 1 << 21
        return "ADRP", v << 12
    if (i & 0x80000000) == 0 and (i & 0x1F00000) == 0x100000:
        immlo = (i >> 29) & 3
        immhi = (i >> 5) & 0x7FFFF
        v = (immhi << 2) | immlo
        if v & (1 << 20):
            v -= 1 << 21
        return "ADR", v
    return "?", 0


with open(SO, "rb") as f:
    for a in SITES:
        f.seek(a - 0x4000)
        w = struct.unpack("<I", f.read(4))[0]
        kind, imm = decode(w)
        if kind == "ADRP":
            res = (a & ~0xFFF) + imm
            print(f"  {a:#x}: {kind} rd={w & 0x1f} imm={imm:#x} -> {res:#x}")
        else:
            print(f"  {a:#x}: {kind} word={w:#010x}")
