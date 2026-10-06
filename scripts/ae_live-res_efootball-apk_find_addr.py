"""find_addr.py <target_va> [...] -- find code that computes an exact address.

Vtables in `.data.rel.ro` cannot be read from this ELF (see census 2g.7), but a
vtable is normally filled by a static initializer that materialises each slot
with an ADRP+ADD pair.  Finding the pair that computes the vtable's *base*
address locates that initializer, and dumping it yields every slot.

Scans the executable segment for ADRP followed by ADD / ADD LSL#12 / LDR that
lands exactly on the target.

  find_addr.py 0x97a2168 0x97a21d8 0x9823660
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


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


targets = [int(a, 16) for a in sys.argv[1:]]
rx_off, rx_va, rx_sz = RX

hits = {t: [] for t in targets}

for va in range(rx_va, rx_va + rx_sz, 4):
    off = va2off(va)
    if off is None:
        break
    w = struct.unpack_from("<I", d, off)[0]
    if (w >> 24) & 0x9F != 0x90:                     # ADRP Xd, #imm
        continue
    rd = w & 0x1F
    imm = sx(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3), 21)
    page = (va & ~0xFFF) + (imm << 12)

    w2 = struct.unpack_from("<I", d, off + 4)[0]
    tgt = None
    kind = None
    if (w2 & 0xFF800000) == 0x91000000:              # ADD Xd, Xn, #imm
        if ((w2 >> 5) & 0x1F) == rd:
            i = (w2 >> 10) & 0xFFF
            if (w2 >> 22) & 1:
                tgt, kind = page + (i << 12), "ADD#12"
            else:
                tgt, kind = page + i, "ADD"
    elif (w2 & 0xFFC00000) == 0xF9400000:            # LDR Xt, [Xn, #imm]
        if ((w2 >> 5) & 0x1F) == rd:
            tgt, kind = page + ((w2 >> 10) & 0xFFF) * 8, "LDR"

    if tgt in hits:
        hits[tgt].append((va, kind))

for t in targets:
    print("=" * 78)
    print("target 0x%08x : %d site(s)" % (t, len(hits[t])))
    print("=" * 78)
    for va, kind in hits[t][:24]:
        print("  0x%08x  %s" % (va, kind))
    print()
