"""glob_xrefs.py -- str_xrefs.py only matches ADRP+ADD landing on the exact
address.  A reader that indexes into a parent struct will ADRP the same page
but ADD a different immediate, then reach the field by a small offset.  This
finds every ADRP to a page plus any following ADD/LDR/STR offset that could
touch a window around the field."""

import os
import struct
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
data = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
rx = None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, o)
    p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
        "<QQQQQQ", data, o + 8)
    if p_type == 1 and (p_flags & 1) and rx is None:
        rx = (p_offset, p_vaddr, p_filesz)

po, pv, pf = rx
code = np.frombuffer(data, dtype="<u4", count=pf // 4, offset=po)
pc = pv + np.arange(code.size, dtype=np.int64) * 4


def sx(x, bits):
    sign = 1 << (bits - 1)
    mask = (1 << bits) - 1
    return ((x & mask) ^ sign) - sign


def adrp_page(idx):
    w = code[idx]
    if ((w >> 24) & 0x9F) != 0x90:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = sx((immhi << 2) | immlo, 21)
    return (pc[idx] & ~0xFFF) + (imm << 12)


def find_window(target, span=0x300):
    page = target & ~0xFFF
    lo, hi = target - span, target + span
    out = []
    m = (np.right_shift(code, 24) & np.uint32(0x9F)) == np.uint32(0x90)
    idx = np.nonzero(m)[0]
    for i in idx:
        pg = adrp_page(i)
        if pg is None or pg != page:
            continue
        # scan forward a few insns for ADD immediate forming an address
        for k in range(i, min(i + 6, code.size)):
            w = int(code[k])
            # ADD (immediate) 64-bit: 1001 0001 0 sh imm12 rn rd
            if (w & 0xFF800000) == 0x91000000:
                imm = (w >> 10) & 0xFFF
                sh = (w >> 22) & 1
                addr = pg + (imm << (12 if sh else 0))
                if lo <= addr <= hi:
                    out.append((int(pc[i]), int(pc[k]), addr, "ADD"))
            # LDR unsigned offset 64-bit / STR unsigned offset 64-bit
            if (w & 0xFFC00000) == 0xF9400000:
                imm = (w >> 10) & 0xFFF
                addr = pg + imm * 8
                if lo <= addr <= hi:
                    out.append((int(pc[i]), int(pc[k]), addr, "LOAD"))
            if (w & 0xFFC00000) == 0xF9000000:
                imm = (w >> 10) & 0xFFF
                addr = pg + imm * 8
                if lo <= addr <= hi:
                    out.append((int(pc[i]), int(pc[k]), addr, "STORE"))
    return out


print("=" * 78)
if len(sys.argv) > 1:
    targets = [(a, int(a, 16)) for a in sys.argv[1:]]
else:
    targets = [("CA-root/key/cert config 0xa4a8478", 0xa4a8478),
               ("public-key buffer 0xa4b0298", 0xa4b0298)]
for name, t in targets:
    print("=" * 78)
    print(name)
    print("=" * 78)
    hits = find_window(t)
    if not hits:
        print("  no ADRP-derived access within +-0x300")
    seen = set()
    for adrp_pc, ins_pc, addr, kind in hits:
        key = (ins_pc, addr)
        if key in seen:
            continue
        seen.add(key)
        print("  ADRP@0x%x  insn@0x%x  -> 0x%x  (%s)%s"
              % (adrp_pc, ins_pc, addr, kind,
                 "   <== EXACT FIELD" if addr == t else ""))
    print()
