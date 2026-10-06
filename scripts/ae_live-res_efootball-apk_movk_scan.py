"""movk_scan.py <addr> [...] -- find MOVZ/MOVK triples that build an address.

`find_addr.py` only catches ADRP+ADD.  A linker that cannot use ADRP (or a
hand-written initializer) materialises a large constant with

    MOVZ Xd, #low16,  LSL #0
    MOVK Xd, #mid16,  LSL #16
    MOVK Xd, #high16, LSL #32

so this scans for those triples sharing a destination register.

  movk_scan.py 0x97a2168 0x97a21d8 0x9823660
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
LOADS, RX = [], None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from("<II", d, o)
    po, pv = struct.unpack_from("<QQ", d, o + 8)
    pf, pm = struct.unpack_from("<QQ", d, o + 32)
    if t == 1:
        LOADS.append((po, pv, pm))
        if fl & 1:
            RX = (po, pv, pf)


def va2off(va):
    for po, pv, pm in LOADS:
        if pv <= va < pv + pm:
            return po + (va - pv)
    return None


MOVK_BASES = {0xD2800000: ("MOVZ", 0), 0xD2A00000: ("MOVZ", 16),
              0xD2C00000: ("MOVZ", 32), 0xD2E00000: ("MOVZ", 48),
              0xF2800000: ("MOVK", 0), 0xF2A00000: ("MOVK", 16),
              0xF2C00000: ("MOVK", 32), 0xF2E00000: ("MOVK", 48)}

rx_off, rx_va, rx_sz = RX

# collect every MOVZ/MOVK immediate, grouped by destination register
by_reg = {}
for va in range(rx_va, rx_va + rx_sz, 4):
    off = va2off(va)
    if off is None:
        break
    w = struct.unpack_from("<I", d, off)[0]
    base = w & 0xFF800000
    if base not in MOVK_BASES:
        continue
    kind, shift = MOVK_BASES[base]
    rd = w & 0x1F
    imm16 = (w >> 5) & 0xFFFF
    by_reg.setdefault(rd, []).append((va, kind, shift, imm16))

print("registers holding MOVZ/MOVK immediates: %d" % len(by_reg))
print()

for target in [int(a, 16) for a in sys.argv[1:]]:
    lo, mid, hi = target & 0xFFFF, (target >> 16) & 0xFFFF, (target >> 32) & 0xFFFF
    print("=" * 78)
    print("target 0x%08x  (low=0x%04x mid=0x%04x high=0x%04x)" % (target, lo, mid, hi))
    print("=" * 78)
    found = False
    for rd, ins in by_reg.items():
        have = {(k, s): i for _, k, s, i in ins}
        if ("MOVZ", 0) in have and ("MOVK", 16) in have and ("MOVK", 32) in have:
            if have[("MOVZ", 0)] == lo and have[("MOVK", 16)] == mid \
               and have[("MOVK", 32)] == hi:
                sites = sorted(v for v, _, _, _ in ins
                               if (_, _) in ((have[("MOVZ", 0)], 0),))
                print("  x%d  built at 0x%08x" % (rd, sites[0]))
                found = True
    if not found:
        print("  no MOVZ/MOVK triple found")
    print()
