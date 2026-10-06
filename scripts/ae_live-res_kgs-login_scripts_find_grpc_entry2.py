#!/usr/bin/env python3
"""Locate the game's gRPC client: who builds the object at vtable 0x9819b70,
and what function contains the vtable store at 0x7b0f7ec.

Then list the whole 0x7b0e000..0x7b12000 gRPC-client region function by
function, so we can see the create/send/read shape to drive.
"""
from __future__ import annotations

import bisect
import os
import re
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
HERE = os.path.dirname(os.path.abspath(__file__))
FDE = os.path.join(HERE, "funcs_eh.txt")
TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(SO, "rb").read()
starts, recs = [], []
for line in open(FDE, encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if m:
        s0, e0 = int(m.group(1), 16), int(m.group(2), 16)
        starts.append(s0)
        recs.append((s0, e0))


def fn_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return recs[i] if i >= 0 and starts[i] <= a < recs[i][1] else (0, 0)


def stext(a, n=70):
    try:
        b = data[a:a + n].split(b"\x00")[0]
        return b.decode("latin1", "replace") if b else ""
    except Exception:
        return ""


def adrp(i, pc):
    if (i & 0x9F000000) != 0x90000000:
        return None
    immlo = (i >> 29) & 3
    immhi = (i >> 5) & 0x7FFFF
    v = (immhi << 2) | immlo
    if v & (1 << 20):
        v -= 1 << 21
    return (pc & ~0xFFF) + (v << 12), i & 0x1F


def add_imm(i):
    if (i & 0xFF800000) != 0x91000000:
        return None
    rn = (i >> 5) & 0x1F
    rd = i & 0x1F
    imm = (i >> 10) & 0xFFF
    if i & (1 << 22):
        imm <<= 12
    return rd, rn, imm


def ldr_lit(i, pc):
    if (i & 0xFF000000) != 0x58000000:
        return None
    imm19 = (i >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= 1 << 19
    return pc + imm19 * 4, i & 0x1F


def find_refs(target, region=(0x28293C0, 0x28293C0 + TEXT_SIZE)):
    page = target & ~0xFFF
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    pending = {}
    hits = []
    for off in range(0, len(text), 4):
        w = struct.unpack_from("<I", text, off)[0]
        pc = TEXT_VADDR + off
        r = adrp(w, pc)
        if r:
            base, rd = r
            pending[rd] = base
            if base == page:
                hits.append(("ADRP", pc, None))
            continue
        a = add_imm(w)
        if a:
            rd, rn, imm = a
            if rn in pending:
                if pending[rn] + imm == target:
                    hits.append(("ADRP+ADD", pc, pc))
            pending.pop(rd, None)
            continue
        r = ldr_lit(w, pc)
        if r:
            t, rt = r
            if t == target:
                hits.append(("LDR", pc, pc))
    return hits


def main():
    print("=== who references vtable 0x9819b70 ===", flush=True)
    for kind, pc, pc2 in find_refs(0x9819B70):
        fs, fe = fn_of(pc)
        print("  %-9s %#x   in fn %#x..%#x (%d bytes)  str=%r"
              % (kind, pc, fs, fe, fe - fs, stext(fs)), flush=True)

    print("\n=== functions in the gRPC client region 0x7b0e000..0x7b12000 ===",
          flush=True)
    for (fs, fe) in recs:
        if 0x7B0E000 <= fs < 0x7B12000:
            print("  %#x..%#x  %5d B  str=%r" % (fs, fe, fe - fs,
                                                  stext(fs)[:50]), flush=True)

    print("\n=== function containing 0x7b0f7ec (vtable store) ===",
          flush=True)
    print("  ", ["%#x..%#x" % fn_of(0x7B0F7EC), ] if False else
          "  fn %s  str=%r" % (["%#x" % v for v in fn_of(0x7B0F7EC)],
                               stext(fn_of(0x7B0F7EC)[0])), flush=True)


if __name__ == "__main__":
    main()
