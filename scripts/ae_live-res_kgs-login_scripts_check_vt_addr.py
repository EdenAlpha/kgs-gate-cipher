#!/usr/bin/env python3
"""Decisive test: are the vtable slots really zero, or am I reading the wrong
address?

The constructor at 0x767eaf0 does:
    adrp x8, #0x97a2000
    add  x8, x8, #0x600
    str  x8, [x19]        -> obj->vtable = 0x97a2600

But .rodata vaddr == file offset only for some segments.  If 0x97a2600 lives
in a segment whose vaddr != file offset, my raw file read was wrong and the
vtable is perfectly fine in the file.
"""
from __future__ import annotations

import struct
import sys

from elftools.elf.elffile import ELFFile

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
VT = 0x97A2600
VT2 = 0x97D4448
TEXT_LO, TEXT_HI = 0x28293C0, 0x8B75140

data = open(SO, "rb").read()


def vaddr_to_off(v):
    with open(SO, "rb") as f:
        for s in ELFFile(f).iter_segments():
            if s["p_type"] != "PT_LOAD":
                continue
            if s["p_vaddr"] <= v < s["p_vaddr"] + s["p_filesz"]:
                return s["p_offset"] + (v - s["p_vaddr"]), s
    return None, None


def main() -> int:
    for vt in (VT, VT2):
        off, seg = vaddr_to_off(vt)
        print(f"=== vtable {vt:#x} ===")
        if off is None:
            print("   not inside any PT_LOAD filesz")
            continue
        print(f"   segment vaddr={seg['p_vaddr']:#x} off={seg['p_offset']:#x} "
              f"filesz={seg['p_filesz']:#x}")
        print(f"   => file offset {off:#x}  (raw vaddr read would be wrong)")
        for i in range(12):
            v = struct.unpack_from("<Q", data, off + i * 8)[0]
            tag = "TEXT" if TEXT_LO <= v < TEXT_HI else ""
            print(f"      [{i:2d}] {v:#018x}  {tag}")
        print()

    # sanity: is vaddr==file offset true for the data segments?
    with open(SO, "rb") as f:
        print("PT_LOAD summary:")
        for s in ELFFile(f).iter_segments():
            if s["p_type"] == "PT_LOAD":
                same = "vaddr==offset" if s["p_vaddr"] == s["p_offset"] else \
                       "DIFFERENT"
                print(f"   vaddr={s['p_vaddr']:#012x} off={s['p_offset']:#012x} "
                      f"filesz={s['p_filesz']:#012x}  {same}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
