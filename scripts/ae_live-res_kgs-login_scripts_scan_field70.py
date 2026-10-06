#!/usr/bin/env python3
"""Find the code that fills the std::string sitting at offset 0x70.

That string is `a` in the live URL template  gate/gate_<a>.php

We look for the idiomatic assignment shape:

    add  x0, xN, #0x70        ; &obj.m_service
    adrp x1, #page            ; a string literal ...
    add  x1, x1, #off
    bl   <string assign>

and print the enclosing function together with the literals it mentions.
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


def insn(a: int) -> int:
    off = TEXT_OFF + (a - TEXT_V)
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def fn_of(a: int) -> tuple[int, int]:
    i = bisect.bisect_right(starts, a) - 1
    if i >= 0 and starts[i] <= a < recs[i][1]:
        return recs[i]
    return (0, 0)


def adrp_target(w: int, a: int):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= 1 << 33
    return (a & ~0xFFF) + imm


def strlit(addr: int) -> str | None:
    if addr <= 0 or addr >= len(data):
        return None
    if data[addr] == 0 or not (32 <= data[addr] < 127):
        return None
    end = data.find(b"\0", addr)
    if end < 0 or end - addr > 70:
        return None
    s = data[addr:end]
    if not all(32 <= c < 127 for c in s):
        return None
    return s.decode()


def literals_in(s: int, e: int) -> list[str]:
    out = []
    for a in range(s, e, 4):
        w = insn(a)
        t = adrp_target(w, a)
        if t is None:
            continue
        # next instruction likely adds the low 12 bits
        w2 = insn(a + 4)
        if (w2 & 0xFF800000) == 0x91000000:
            off = (w2 >> 10) & 0xFFF
            if (w2 & 0x400000) == 0:
                lit = strlit(t + off)
                if lit:
                    out.append(lit)
    return out


def main() -> int:
    lo = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x7A00000
    hi = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x7B40000

    fns: dict[int, list[int]] = {}
    for a in range(TEXT_V, TEXT_V + TEXT_SIZE, 4):
        if not lo <= a < hi:
            continue
        w = insn(a)
        # ADD (immediate) 64-bit, shift 0, imm = 0x70, Rd = x0..x7
        if (w & 0xFF800000) != 0x91000000 or (w & 0x400000):
            continue
        if ((w >> 10) & 0xFFF) != 0x70:
            continue
        # must be followed soon by an adrp -> literal load
        if adrp_target(insn(a + 4), a + 4) is None and \
           adrp_target(insn(a + 8), a + 8) is None and \
           adrp_target(insn(a + 12), a + 12) is None and \
           adrp_target(insn(a + 16), a + 16) is None and \
           adrp_target(insn(a + 20), a + 20) is None:
            continue
        s, _ = fn_of(a)
        fns.setdefault(s, []).append(a)

    for s in sorted(fns):
        e = fn_of(s)[1]
        lits = literals_in(s, e)
        print(f"  {s:#x}..{e:#x}  hits={[hex(x) for x in fns[s][:4]]}")
        for lit in lits[:14]:
            print(f"        {lit!r}")
    print(f"total {len(fns)} functions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
