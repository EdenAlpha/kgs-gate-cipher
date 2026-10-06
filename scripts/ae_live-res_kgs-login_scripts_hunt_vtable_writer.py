#!/usr/bin/env python3
"""If the phone can run this binary, something must fill the zeroed vtables
at startup.  Find who writes them.

Strategy: the game's own init_array runs before main().  Walk those entries
and look for a routine that walks .data.rel.ro and writes code addresses into
it -- the classic "vtable self-relocation" patcher some shipping builds use
instead of shipping a .rela.dyn.

Also: look for the CMD_GET_SERVER_ENV ctor's vtable (0x97a2600) being
referenced by *any* instruction, not just stores.
"""
from __future__ import annotations

import re
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48
VT = 0x97A2600
PAGE = VT & ~0xFFF
OFF = VT & 0xFFF

data = open(SO, "rb").read()


def insn(a: int) -> int:
    o = TEXT_OFF + (a - TEXT_V)
    if o < 0 or o + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, o)[0]


def main() -> int:
    # ---- 1. init_array -------------------------------------------------
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    dyn = {}
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] == 2:      # PT_DYNAMIC
            off = struct.unpack_from("<Q", data, o + 0x18)[0]
            sz = struct.unpack_from("<Q", data, o + 0x20)[0]
            j = 0
            while j + 16 <= sz:
                t, v = struct.unpack_from("<QQ", data, off + j)
                if t == 0:
                    break
                dyn[t] = v
                j += 16
    ia_v = dyn.get(25) or dyn.get(0x19)
    ia_sz = dyn.get(27) or dyn.get(0x1b)
    print(f"INIT_ARRAY vaddr={ia_v:#x} size={ia_sz:#x} "
          f"({(ia_sz or 0)//8} entries)")

    # ---- 2. any instruction that materialises 0x97a2600? ---------------
    print(f"\n=== references to the vtable {VT:#x} ===")
    hits = 0
    for p in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        pc = TEXT_V + (p - TEXT_OFF)
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= 1 << 33
        if (pc & ~0xFFF) + imm != PAGE:
            continue
        rn = (w >> 5) & 31
        for k in range(1, 5):
            w2 = insn(pc + 4 * k)
            if (w2 & 0xFFC003E0) == 0x91000000 and ((w2 >> 5) & 31) == rn:
                i2 = (w2 >> 10) & 0xFFF
                if (w2 >> 22) & 1:
                    i2 <<= 12
                if (pc & ~0xFFF) + imm + i2 == VT:
                    print(f"   adrp+add at {pc:#x} (+{k})")
                    hits += 1
    print(f"   total: {hits}")

    # ---- 3. anything that looks like a self-relocation patcher ---------
    # A patcher walks a region and writes (base + something) into 8-byte
    # slots.  Signature: a loop with an add of the image base (0x10000000000
    # is our base, but in-file it would be an ADRP of a low page) plus a
    # str of a 64-bit register.  Look for dense adrp/str pairs in the
    # .init_array targets only -- too noisy otherwise.
    print("\n=== init_array contents (file vaddrs) ===")
    if ia_v:
        # .data vaddr==file offset for this segment
        for k in range((ia_sz or 0) // 8):
            try:
                v = struct.unpack_from("<Q", data, ia_v + k * 8)[0]
            except Exception:
                break
            if v:
                print(f"   [{k:3d}] {v:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
