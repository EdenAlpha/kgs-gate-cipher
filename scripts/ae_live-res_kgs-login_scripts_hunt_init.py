#!/usr/bin/env python3
"""The phone runs this same binary, so the zeroed vtables must be filled in at
startup.  DT_INIT_ARRAY has 11,829 entries -- that is where the patcher lives.

Search those constructors for code that writes 8-byte code addresses into
.data.rel.ro, i.e. a vtable self-relocation pass.
"""
from __future__ import annotations

import re
import struct
import sys

from elftools.elf.elffile import ELFFile

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_LO, TEXT_HI = 0x28293C0, 0x8B75140
VT = 0x97A2600

data = open(SO, "rb").read()


def main() -> int:
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        seg = next(s for s in elf.iter_segments() if s["p_type"] == "PT_DYNAMIC")
        ia_v = ia_sz = None
        for t in seg.iter_tags():
            if t.entry.d_tag == "DT_INIT_ARRAY":
                ia_v = t.entry.d_ptr
            elif t.entry.d_tag == "DT_INIT_ARRAYSZ":
                ia_sz = t.entry.d_val
    print(f"INIT_ARRAY @ {ia_v:#x}  {ia_sz} bytes "
          f"({ia_sz // 8} entries)")

    # vaddr == file offset in the data segment for this binary
    entries = []
    for k in range(ia_sz // 8):
        v = struct.unpack_from("<Q", data, ia_v + k * 8)[0]
        if v:
            entries.append(v)
    print(f"non-zero entries: {len(entries)}")
    print("first 12:", [hex(v) for v in entries[:12]])

    text = set(entries)
    # Which of them touch the vtable page 0x97a2000 at all?
    print(f"\n=== init constructors referencing vtable page "
          f"{VT & ~0xFFF:#x} ===")
    TEXT_V, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48
    page = VT & ~0xFFF
    touched = []

    def insn(a):
        o = TEXT_OFF + (a - TEXT_V)
        return struct.unpack_from("<I", data, o)[0] if 0 <= o <= len(data) - 4 else 0

    for a in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE, 4):
        w = struct.unpack_from("<I", data, a)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        pc = TEXT_V + (a - TEXT_OFF)
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= 1 << 33
        if (pc & ~0xFFF) + imm != page:
            continue
        rn = (w >> 5) & 31
        for k in range(1, 6):
            w2 = insn(pc + 4 * k)
            if (w2 & 0xFFC003E0) != 0x91000000 or ((w2 >> 5) & 31) != rn:
                continue
            i2 = (w2 >> 10) & 0xFFF
            if (w2 >> 22) & 1:
                i2 <<= 12
            if (pc & ~0xFFF) + imm + i2 == VT:
                print(f"   {pc:#x} materialises {VT:#x}")
                touched.append(pc)
    print(f"   total refs: {len(touched)}")
    if not touched:
        print("\n   -> no code references that vtable at all; the object must "
              "be\n      constructed differently at runtime.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
