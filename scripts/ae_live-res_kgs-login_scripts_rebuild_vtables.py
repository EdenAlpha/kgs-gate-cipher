#!/usr/bin/env python3
"""Materialise zeroed vtables so the game's own code can actually run.

Why this is needed (proven, not guessed):
  * the ctor at 0x767eaf0 does adrp/add/str of 0x97a2600 into obj[0]
  * every slot at 0x97a2600 is zero in the file
  * the ELF has no .rela.dyn and no DT_RELR, so the loader never fills them
  * therefore every virtual call in the game branches to address 0

How we recover them without a linker:
  A C++ vtable's slots are the class's virtual functions, emitted in
  declaration order, which for clang means *link order within the class's
  method group*.  We therefore:
    1. find every constructor in the binary that installs a vtable V
    2. take the contiguous function-record group around that constructor
    3. write those functions into V, in order
This is a reconstruction, so we verify it by running the game: if the harness
gets past a virtual call that used to fault at 0, the values are right.

We start with the one class the login path needs.
"""
from __future__ import annotations

import bisect
import re
import struct
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48
DATA_LO, DATA_HI = 0x8B75140, 0xA000000        # the zeroed data segments

data = open(SO, "rb").read()
starts, recs = [], []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if m:
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        starts.append(s)
        recs.append((s, e))


def word(a):
    o = TEXT_OFF + (a - TEXT_V)
    return struct.unpack_from("<I", data, o)[0] if 0 <= o <= len(data) - 4 else 0


def adrp_target(i_a):
    x = word(i_a)
    if (x & 0x9F000000) != 0x90000000:
        return None
    immlo = (x >> 29) & 3
    immhi = (x >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= 1 << 33
    return (i_a & ~0xFFF) + imm


def find_vtable_stores():
    """Every (ctor_addr, vtable) pair: adrp/add/str of a data address."""
    out = []
    for p in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE, 4):
        a = TEXT_V + (p - TEXT_OFF)
        ad = adrp_target(a)
        if ad is None or not (DATA_LO <= ad < DATA_HI):
            continue
        rd = word(a) & 0x1F
        y = word(a + 4)
        # ADD (immediate, 64-bit): sf/op/S=10010001, shift(23:22) is PART OF
        # the opcode, so mask it out.  Previous mask 0xFFC003E0 wrongly kept
        # bit 22 and so rejected every LSL#12 form -- which is why the scan
        # missed the one site verified by hand.
        if (y & 0xFF800000) != 0x91000000 or ((y >> 5) & 0x1F) != rd:
            continue
        imm = (y >> 10) & 0xFFF
        if (y >> 22) & 1:
            imm <<= 12
        vt = ad + imm
        if not (DATA_LO <= vt < DATA_HI):
            continue
        # the store may be a few instructions later (register shuffles)
        for k in range(2, 7):
            z = word(a + 4 * k)
            if (z & 0xFFC00000) in (0xF9000000, 0xA9000000, 0xF8000000):
                out.append((a, vt))
                break
    return out


def main() -> int:
    stores = find_vtable_stores()
    print(f"vtable install sites found: {len(stores)}")
    uniq = {}
    for a, vt in stores:
        uniq.setdefault(vt, []).append(a)
    print(f"distinct vtables referenced: {len(uniq)}")

    import bisect as bs
    for vt in (0x97A2600, 0x97D4448):
        at = uniq.get(vt, [])
        print(f"\n=== vtable {vt:#x} ===")
        print(f"  installed at: {[hex(x) for x in at]}")
        if not at:
            continue
        ctor = at[0]
        i = bs.bisect_right(starts, ctor) - 1
        s = recs[i][0]
        print(f"  ctor function: {s:#x}..{recs[i][1]:#x}")
        # the class's methods: contiguous records around the ctor
        j = i
        grp = []
        while j > 0 and recs[j - 1][0] >= s - 0x8000:
            grp.append(recs[j - 1][0])
            j -= 1
        grp.append(s)
        j = i
        while j + 1 < len(recs) and recs[j + 1][0] <= recs[i][1] + 0x8000:
            j += 1
            grp.append(recs[j][0])
        grp = sorted(set(grp))
        print(f"  candidate method list ({len(grp)}):")
        for g in grp:
            print(f"     {g:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
