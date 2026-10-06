"""page_users.py -- every ADRP to a given page, with the instructions after it.

Used to prove whether the log-sink slot at 0x9c14870 has any writer besides
the one already found.  glob_xrefs only recognises ADD/SUB-free addressing;
this walks each ADRP site forward and prints the whole sequence so any
address arithmetic (including two-step ADD/SUB or a pre/post-index store) is
visible.

  page_users.py <page_va>
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"efootball-apk\native\lib\arm64-v8a\libUE4.so"
import os
if not os.path.exists(LIB):
    LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from("<II", d, o)
    po, pv = struct.unpack_from("<QQ", d, o + 8)
    pf, pm = struct.unpack_from("<QQ", d, o + 32)
    ph.append((t, fl, po, pv, pf, pm))

RX = [(po, pv, pf) for t, fl, po, pv, pf, pm in ph if t == 1 and (fl & 1)][0]
R_OFF, R_VA, R_SZ = RX


def va2off(va):
    for t, fl, po, pv, pf, pm in ph:
        if t == 1 and pv <= va < pv + pf:
            return po + (va - pv)
    return None


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


page = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x9C14000
AFTER = int(sys.argv[2]) if len(sys.argv) > 2 else 12

print("=" * 78)
print("every ADRP landing on page 0x%x, +%d instructions" % (page, AFTER))
print("=" * 78)

sites = []
for off in range(0, R_SZ, 4):
    w = struct.unpack_from("<I", d, R_OFF + off)[0]
    if ((w >> 24) & 0x9F) != 0x90:
        continue
    pc = R_VA + off
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = sx((immhi << 2) | immlo, 21)
    tgt = (pc & ~0xFFF) + (imm << 12)
    if tgt == page:
        sites.append(pc)

print("ADRP sites on this page: %d" % len(sites))
for pc in sites:
    print()
    print("-" * 78)
    print("ADRP @0x%x" % pc)
    for i in range(AFTER):
        a = pc + i * 4
        o = va2off(a)
        if o is None:
            break
        w = struct.unpack_from("<I", d, o)[0]
        # crude decode: ADD/SUB immediate, LDR/STR unsigned offset,
        # pre/post-index LDR/STR, MOVZ/MOVK, BL/B
        note = ""
        if (w & 0xFF800000) == 0x91000000:
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            imm12 = (w >> 10) & 0xFFF
            sh = (w >> 22) & 1
            note = "ADD  x%d, x%d, #0x%x%s" % (rd, rn, imm12 << (12 if sh else 0),
                                                "" if not sh else " (lsl12)")
        elif (w & 0xFF800000) == 0xD1000000:
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            imm12 = (w >> 10) & 0xFFF
            sh = (w >> 22) & 1
            note = "SUB  x%d, x%d, #0x%x" % (rd, rn, imm12 << (12 if sh else 0))
        elif (w & 0xFFC00000) == 0xF9400000:
            note = "LDR  x%d, [x%d, #0x%x]  -> page+0x%x" % (
                w & 0x1F, (w >> 5) & 0x1F, ((w >> 10) & 0xFFF) * 8,
                ((w >> 10) & 0xFFF) * 8)
        elif (w & 0xFFC00000) == 0xF9000000:
            note = "STR  x%d, [x%d, #0x%x]  -> page+0x%x  <== STORE" % (
                w & 0x1F, (w >> 5) & 0x1F, ((w >> 10) & 0xFFF) * 8,
                ((w >> 10) & 0xFFF) * 8)
        elif (w & 0xFFE00C00) == 0xF8000400:
            note = "STR  pre/post-index  <== STORE (indexed)"
        elif (w & 0xFFE00C00) == 0xF8400400:
            note = "LDR  pre/post-index"
        elif (w & 0xFF800000) == 0xD2800000:
            note = "MOVZ x%d, #0x%x" % (w & 0x1F, ((w >> 5) & 0xFFFF) << (
                ((w >> 21) & 3) * 16))
        elif (w & 0xFF800000) == 0xF2800000:
            note = "MOVK x%d, #0x%x" % (w & 0x1F, ((w >> 5) & 0xFFFF) << (
                ((w >> 21) & 3) * 16))
        elif (w & 0xFC000000) == 0x94000000:
            note = "BL   0x%x" % (a + sx(w & 0x3FFFFFF, 26) * 4)
        elif (w & 0xFC000000) == 0x14000000:
            note = "B    0x%x" % (a + sx(w & 0x3FFFFFF, 26) * 4)
        elif w == 0xD65F03C0:
            note = "ret"
        elif (w & 0xFF000000) in (0x52800000, 0x12800000):
            note = "MOV  w%d, #0x%x" % (w & 0x1F, ((w >> 5) & 0xFFFF) << (
                ((w >> 21) & 3) * 16))
        print("   0x%08x: 0x%08x  %s" % (a, w, note))
