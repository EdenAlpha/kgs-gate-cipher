#!/usr/bin/env python3
"""Find ADRP/ADR references to a target vaddr inside .text."""
from __future__ import annotations
import os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48


def adrp(i, pc):
    if (i & 0x9F000000) != 0x90000000:
        return None
    immlo = (i >> 29) & 3
    immhi = (i >> 5) & 0x7FFFF
    v = (immhi << 2) | immlo
    if v & (1 << 20):
        v -= 1 << 21
    return (pc & ~0xFFF) + (v << 12), i & 0x1F


def adr(i, pc):
    if (i & 0x9F000000) != 0x10000000:
        return None
    immlo = (i >> 29) & 3
    immhi = (i >> 5) & 0x7FFFF
    v = (immhi << 2) | immlo
    if v & (1 << 20):
        v -= 1 << 21
    return pc + v, i & 0x1F


def add_imm(i):
    """ADD Xd, Xn, #imm12 -> (rd, rn, imm) or None"""
    if (i & 0xFF800000) != 0x91000000:
        return None
    rn = (i >> 5) & 0x1F
    rd = i & 0x1F
    imm = (i >> 10) & 0xFFF
    if i & (1 << 22):        # shift 12
        imm <<= 12
    return rd, rn, imm


def ldr_lit(i, pc):
    """LDR Xt, label -> (target, rt)"""
    if (i & 0xFF000000) != 0x58000000:
        return None
    imm19 = (i >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= 1 << 19
    return pc + imm19 * 4, i & 0x1F


def main():
    target = int(sys.argv[1], 16)
    page = target & ~0xFFF
    want = target - page
    print(f"target {target:#x}  page {page:#x} off {want:#x}", flush=True)

    blob = open(SO, "rb").read()
    text = blob[TEXT_OFF:TEXT_OFF + TEXT_SIZE]

    # ADRP results, keyed by register within a small window
    pending = {}
    hits = []
    n = len(text)
    for off in range(0, n, 4):
        w = struct.unpack_from("<I", text, off)[0]
        pc = TEXT_VADDR + off

        r = adrp(w, pc)
        if r:
            base, rd = r
            pending[rd] = (base, pc)
            if base == page:
                hits.append(("ADRP", pc, None))
            continue
        r = adr(w, pc)
        if r:
            a, rd = r
            pending.pop(rd, None)
            if a == target:
                hits.append(("ADR", pc, None))
            continue
        a = add_imm(w)
        if a:
            rd, rn, imm = a
            if rn in pending:
                base, src = pending[rn]
                if base + imm == target:
                    hits.append(("ADRP+ADD", src, pc))
            pending.pop(rd, None)
            continue
        r = ldr_lit(w, pc)
        if r:
            t, rt = r
            if t == target:
                hits.append(("LDR-lit", pc, pc))

    print(f"hits: {len(hits)}")
    for h in [x for x in hits if x[1] is not None][:80]:
        print("   ", h, hex(h[1]), hex(h[2]) if h[2] else "")
    print("--- ADRP-only (first 5) ---")
    for h in [x for x in hits if x[1] is None][:5]:
        print("   ", h)


if __name__ == "__main__":
    main()
