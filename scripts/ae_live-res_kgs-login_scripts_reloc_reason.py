#!/usr/bin/env python3
"""Reconstruct the missing R_AARCH64_RELATIVE fixups.

The file has no .rela.dyn and no DT_RELR, yet every vtable slot, every
.init_array entry and every GOT-adjacent pointer is zero on disk and correct
after Android's loader maps it.  The linker emits *implicit* relative
relocations for such binaries; the loader is told the load address and writes
base+addend into every such slot.

We can do exactly the same thing: the addend is already in the file, it is
simply encoded as a raw virtual address (which is what base+0 looks like when
base is 0).  So a vtable slot that is 0 in the file has addend 0, and a slot
holding a raw vaddr has addend == that vaddr.  The value we must write is
base + addend.

The catch: slots holding 0 carry no addend, so they must be relocated as 0 --
which is exactly what makes them useless.  Unless... the vtable is not
zero-filled data but a *different* kind of object.  This script measures how
many zero runs exist and checks whether any run is preceded by a length or
type tag, i.e. whether the vtable is really a runtime-built structure.
"""
from __future__ import annotations

import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
VT = 0x97A2600
IA = 0x98BD898

data = open(SO, "rb").read()


def main() -> int:
    print(f"INIT_ARRAY at {IA:#x}: first 8 slots all zero "
          f"(normal: implicit RELATIVE relocs)")
    print(f"vtable     at {VT:#x}: all slots zero")
    print()
    print("If BOTH are implicit-relative, the loader writes base+addend at")
    print("load time.  For the vtable that means base+0 == base, which cannot")
    print("be a function pointer -- so these slots must be filled by the")
    print("application, not the loader.")
    print()

    # Which code passes near the vtable?  Scan for ADRP to its page with ANY
    # use (not just +0x600), to find the owning class's methods.
    TEXT_V, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48
    page = VT & ~0xFFF
    print(f"=== all ADRP to page {page:#x} (any offset) ===")
    seen = 0
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
        if (pc & ~0xFFF) + imm == page:
            rd = w & 0x1F
            print(f"   {pc:#x}  adrp x{rd}")
            seen += 1
            if seen > 40:
                break
    print(f"   shown: {seen}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
