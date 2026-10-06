#!/usr/bin/env python3
"""Count every 'adrp+add -> text address' site in .text, and every store of
such a value.  Correct addressing throughout:

    file offset p  ->  vaddr = TEXT_V + (p - TEXT_OFF)
"""
from __future__ import annotations

import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48
TEXT_LO, TEXT_HI = 0x28293C0, 0x8B75140

data = open(SO, "rb").read()
WORDS = [struct.unpack_from("<I", data, TEXT_OFF + 4 * i)[0]
         for i in range(TEXT_SIZE // 4)]
N = len(WORDS)


def w(i):
    return WORDS[i] if 0 <= i < N else 0


def vaddr(i):
    return TEXT_V + 4 * i


def adrp_target(i):
    x = w(i)
    if (x & 0x9F000000) != 0x90000000:
        return None
    immlo = (x >> 29) & 3
    immhi = (x >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= 1 << 33
    return (vaddr(i) & ~0xFFF) + imm


def main() -> int:
    print("=== adrp+add pairs that build a .text address ===")
    made = {}
    sites = 0
    for i in range(N - 1):
        ad = adrp_target(i)
        if ad is None:
            continue
        rd = w(i) & 0x1F
        nxt = w(i + 1)
        if (nxt & 0xFFC003E0) != 0x91000000:
            continue
        if ((nxt >> 5) & 0x1F) != rd:
            continue
        imm = (nxt >> 10) & 0xFFF
        if (nxt >> 22) & 1:
            imm <<= 12
        val = ad + imm
        if TEXT_LO <= val < TEXT_HI:
            sites += 1
            made.setdefault(val, []).append(i)
    print(f"   sites: {sites}   distinct targets: {len(made)}")
    print(f"   sanity: 0x767eb04 in made? "
          f"{any(abs(v-0x767eb04) < 4 for v in ())}")
    for tgt in list(made)[:10]:
        print(f"   {tgt:#x}  x{sites if False else len(made[tgt])}")

    # does anything store into a table region built from a DATA adrp?
    print("\n=== 'str x,[xD,#imm]' where xD came from a data adrp+add ===")
    store_sites = 0
    for i in range(N - 6):
        ad = adrp_target(i)
        if ad is None:
            continue
        if TEXT_LO <= ad < TEXT_HI:
            continue                       # only data pages
        rd = w(i) & 0x1F
        nxt = w(i + 1)
        if (nxt & 0xFFC003E0) != 0x91000000 or ((nxt >> 5) & 0x1F) != rd:
            continue
        for k in range(2, 7):
            x = w(i + k)
            if (x & 0xFFC003FF) == 0xF9000000:      # str xt, [xn, #imm]
                rn = (x >> 5) & 0x1F
                if rn == rd:
                    store_sites += 1
                break
    print(f"   candidate data-table stores: {store_sites}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
