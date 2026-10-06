#!/usr/bin/env python3
"""Recover vtable -> function maps by scanning the whole image for
vtable-shaped runs of text pointers.

Why this works when .rela.dyn is absent: the linker stored the vtable slot
values directly in .data.rel.ro for most classes (a run of 12 was found at
0x9951090).  Classes whose slots are zero are the ones we have to identify and
recover individually -- but the image clearly is not uniformly unrelocated, so
the previous "there are no relocations" conclusion was wrong.
"""
from __future__ import annotations

import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_LO = 0x28293C0
TEXT_HI = 0x8B75140          # end of the executable PT_LOAD
MIN_RUN = 3

# the vtable the CMD_GET_SERVER_ENV ctor installs into the object
WANT_VT = 0x97D4448


def main() -> int:
    data = open(SO, "rb").read()
    print("scanning every PT_LOAD for vtable-shaped runs...", flush=True)

    segs = [(0x0, 0x28253B0), (0x8B75140, 0xD8DB80), (0x9906CC0, 0x63D84)]
    total = 0
    tables: dict[int, int] = {}
    for base, size in segs:
        blob = data[base:base + size]
        n = len(blob) // 8
        prev = False
        begin = 0
        for k in range(n):
            v = struct.unpack_from("<Q", blob, k * 8)[0]
            ok = TEXT_LO <= v < TEXT_HI
            if ok and not prev:
                begin = k
            if not ok and prev:
                if k - begin >= MIN_RUN:
                    total += 1
                    tables[base + begin * 8] = k - begin
            prev = ok
    print(f"  vtable-shaped tables found: {total}")

    if WANT_VT in tables:
        print(f"\n*** the ctor's vtable {WANT_VT:#x} IS present, "
              f"{tables[WANT_VT]} slots")
    else:
        print(f"\n*** the ctor's vtable {WANT_VT:#x} is NOT in that set "
              f"(its slots are zero) -- it is one of the unrecovered classes")

    print(f"\nlargest tables:")
    for a, l in sorted(tables.items(), key=lambda x: -x[1])[:20]:
        print(f"   {a:#x}  {l} slots")
    return 0


if __name__ == "__main__":
    sys.exit(main())
