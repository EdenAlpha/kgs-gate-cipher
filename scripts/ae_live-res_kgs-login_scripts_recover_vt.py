#!/usr/bin/env python3
"""Can the vtable contents be RECOVERED from the constructor + call sites?

The linker wrote zeros because these are R_AARCH64_RELATIVE relocations whose
addend is stored elsewhere (or the slots are simply linker-omitted).  Either
way the *values* are recoverable from the binary, because a C++ vtable's slots
are the virtual functions of the class, and every one of them is the target of
some `blr` reached from code that did `ldr xN, [xM, #slot]`.

This reconstructs the vtable for the class used by 0x767eaf0 (the CMD_GET_
SERVER_ENV constructor) by finding the functions in the same compilation
neighbourhood and by following who calls through the object's vtable.

Concretely, for a UE4 task object the layout is:
    obj[0x00] vtable
    obj[0x08..] members
so a virtual call looks like:  ldr xN,[x0] ; ldr xF,[xN,#slot] ; blr xF
We find all sites of that shape on objects whose vtable is 0x97a2600.
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
VT = 0x97A2600
PAGE = VT & ~0xFFF

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


def adrp_page(w, pc):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= 1 << 33
    return (pc & ~0xFFF) + imm


def main() -> int:
    """Who stores VT into an object (the constructor), and what is around it?

    The set of virtual functions is the set of all `blr` targets reached
    through a vtable load.  Instead of guessing, exploit a simpler fact:
    a vtable's slots point at functions that are typically *adjacent* in
    .text -- the compiler emits them together.  The constructor at 0x767eaf0
    sits in a class whose other methods are nearby.  So enumerate the
    functions in the same region and treat them as the candidate set.
    """
    print(f"=== functions near the CMD_GET_SERVER_ENV ctor 0x767eaf0 ===")
    s, e = fn_of(0x767EAF0)
    print(f"ctor lives in {s:#x}..{e:#x}")
    lo = max(0, starts[starts.index(s)] - 1) if s in starts else 0
    print("neighbouring function records:")
    try:
        i = starts.index(s)
    except ValueError:
        i = bisect.bisect_right(starts, s) - 1
    for k in range(max(0, i - 6), min(len(recs), i + 7)):
        print(f"   {recs[k][0]:#x}..{recs[k][1]:#x}  "
              f"len={recs[k][1]-recs[k][0]:#x}")

    print(f"\n=== who writes VT into an object? ===")
    hits = 0
    for p in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE, 4):
        w = insn(TEXT_V + (p - TEXT_OFF))
        if adrp_page(w, TEXT_V + (p - TEXT_OFF)) != PAGE:
            continue
        pc = TEXT_V + (p - TEXT_OFF)
        rn = (w >> 5) & 0x1F
        for k in range(1, 5):
            w2 = insn(pc + 4 * k)
            if (w2 & 0xFFC003E0) == 0x91000000 and ((w2 >> 5) & 0x1F) == rn:
                i2 = (w2 >> 10) & 0xFFF
                if (w2 >> 22) & 1:
                    i2 <<= 12
                if (pc & ~0xFFF) + adrp_page(w, pc) + i2 == VT:
                    print(f"   ctor at {pc:#x} stores {VT:#x}")
                    hits += 1
    print(f"   total: {hits}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
