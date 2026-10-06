#!/usr/bin/env python3
"""Find code that STORES to an absolute address (e.g. a .bss config table).

Static pointer tables are zero in the file (.rela.dyn), so the only way to find
who configures one is to scan ADRP/ADR+ADD and look for a following str/stp
that targets the resulting register.

    python xref_store.py 0xa4b0218
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


def fn_of(a: int):
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


def adr_target(w: int, a: int):
    if (w & 0x9F000000) != 0x10000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo)
    if imm & (1 << 20):
        imm -= 1 << 21
    return a + imm


def add_imm(w: int, a: int, reg: int):
    """ADD (imm)64-bit shift-0 -> new value of reg."""
    if (w & 0xFF800000) != 0x91000000:
        return None
    if (w & 31) != reg:
        return None
    sh = (w >> 22) & 1
    imm = (w >> 10) & 0xFFF
    if sh:
        imm <<= 12
    rd = (w >> 5) & 31
    return reg, rd, imm


def is_store(w: int) -> bool:
    # STR (immediate, unsigned offset) 64-bit: 11111000 01
    # STP 64-bit signed offset: 10101001 00 (pre/positive) / 0b10101001
    top = w >> 22
    # STR imm64 unsigned: op 1, 111 000 01  -> w>>22 == 0x3E1 range
    if (w & 0xFFC00000) == 0xF9000000:
        return True          # str x, [xn, #imm]
    if (w & 0xFFC00000) == 0xF9800000:
        return True          # prfm-ish / str (lit) leave
    # STP (offset) 64-bit: 10101001 00 => 0xA9000000..0xA97F0000
    if (w & 0xFFC00000) == 0xA9000000:
        return True          # stp xt1, xt2, [xn, #imm]  (positive offset)
    if (w & 0xFFC00000) == 0xA9800000:
        return True          # stp pre-index
    if (w & 0xFFC00000) == 0xA8800000:
        return True          # ldp/ldp post - careful
    del top
    return False


def main() -> int:
    target = int(sys.argv[1], 16)
    lo = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    hi = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0
    if hi == 0:
        lo, hi = TEXT_V, TEXT_V + TEXT_SIZE

    hits = []
    for a in range(TEXT_V, TEXT_V + TEXT_SIZE, 4):
        if not lo <= a < hi:
            continue
        w = insn(a)
        base = adrp_target(w, a) if (w & 0x9F000000) == 0x90000000 \
            else adr_target(w, a)
        if base is None:
            continue
        reg = w & 31
        # walk up to 8 following instructions, tracking reg through adds
        cur, cur_reg = base, reg
        for k in range(1, 9):
            w2 = insn(a + 4 * k)
            r = add_imm(w2, a + 4 * k, cur_reg)
            if r:
                _, nrd, imm = r
                cur += imm
                cur_reg = nrd
                continue
            # a store using cur_reg as base
            if is_store(w2):
                # Rn field for str/stp is bits 5..9
                rn = (w2 >> 5) & 31
                if rn == cur_reg and lo <= cur <= hi or (rn == cur_reg):
                    if cur == target:
                        hits.append((a, cur))
                        break
            if is_store(w2):
                rn = (w2 >> 5) & 31
                if rn == cur_reg and cur == target:
                    break
            # stop if reg is clobbered by an unrelated write
            if (w2 & 31) == cur_reg and not r:
                break

    seen = set()
    for a, _ in hits:
        s, e = fn_of(a)
        if (s, a) in seen:
            continue
        seen.add((s, a))
        print(f"  insn {a:#x}  fn {s:#x}..{e:#x}")
    print(f"total {len(hits)} stores -> {target:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
