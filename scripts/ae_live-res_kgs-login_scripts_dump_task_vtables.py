#!/usr/bin/env python3
"""Dump the task vtables in the 0x9828600..0x9828900 region.

State 2 of the login SM news up an object whose vtable is 0x98286e8, and
state 10 calls vtable[7] then vtable[5] on ctx->[0x288].  Reading the vtable
tells us exactly what those calls do.
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
FDE = os.path.join(HERE, "funcs_eh.txt")


def load_fde():
    out = []
    with open(FDE, encoding="utf-8") as f:
        for line in f:
            p = line.split()
            out.append((int(p[0], 16), int(p[1], 16)))
    return out


def enclosing(fde, addr):
    lo, hi = 0, len(fde) - 1
    best = None
    while lo <= hi:
        m = (lo + hi) // 2
        if fde[m][0] <= addr:
            best = m
            lo = m + 1
        else:
            hi = m - 1
    if best is None:
        return None
    a, b = fde[best]
    return (a, b) if a <= addr < b else None


def main():
    fde = load_fde()
    with open(SO, "rb") as f:
        f.seek(0x9828500)          # .rodata: offset == vaddr
        raw = f.read(0x400)

    print("VTABLE REGION 0x9828500..0x9828900  (qwords)")
    print("=" * 74)
    for off in range(0, len(raw), 8):
        at = 0x9828500 + off
        v = struct.unpack_from("<Q", raw, off)[0]
        if v == 0:
            continue
        e = enclosing(fde, v)
        if e and v == e[0]:
            tag = f"FN {v:#x} size {e[1]-e[0]:#x}"
        elif e:
            tag = f"fn {e[0]:#x}+{v-e[0]:#x}"
        else:
            tag = f"{v:#x}"
        sel = " >>" if at in (0x98286e8, 0x98287f0) else "   "
        print(f"  {sel} {at:#x}: {v:#018x}  {tag}")

    # ---- the two vtables we care about, entry by entry ---------------
    for vt in (0x98286E8, 0x98287F0):
        print("\n" + "=" * 74)
        print(f"VTABLE {vt:#x}  (16 entries)")
        print("=" * 74)
        with open(SO, "rb") as f:
            f.seek(vt)
            data = f.read(16 * 8)
        for i in range(16):
            v = struct.unpack_from("<Q", data, i * 8)[0]
            if v == 0:
                print(f"  [{i:2d}] +{i*8:#05x}  (null)")
                continue
            e = enclosing(fde, v)
            if e and v == e[0]:
                tag = f"FN {v:#x} size {e[1]-e[0]:#x}"
            elif e:
                tag = f"fn {e[0]:#x}+{v-e[0]:#x}"
            else:
                tag = f"{v:#x}"
            mark = "  <== vtable[7]" if i == 7 else \
                "  <== vtable[5]" if i == 5 else ""
            print(f"  [{i:2d}] +{i*8:#05x}  {v:#018x}  {tag}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
