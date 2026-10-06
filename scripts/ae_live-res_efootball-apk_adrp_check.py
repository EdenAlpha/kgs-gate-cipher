"""adrp_check.py -- decode the real ADRP target at the log-sink probe,
using program headers for VA<->offset, not an assumed identity map.
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from("<II", d, o)
    po, pv, _, pf, _, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
    if t == 1:
        ph.append((po, pv, pf, fl))
        print("PT_LOAD off=0x%-10x va=0x%-10x filesz=0x%-10x flags=%d"
              % (po, pv, pf, fl))


def va2off(va):
    for po, pv, pf, _ in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


def off2va(off):
    for po, pv, pf, _ in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


print()
print("identity check:")
for o in (10329029, 12231442, 10197274):
    print("   off=%-10d -> VA=0x%x" % (o, off2va(o)))


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


def adrp_target(d, va):
    o = va2off(va)
    if o is None:
        return None, None
    w = struct.unpack_from("<I", d, o)[0]
    if ((w >> 24) & 0x9F) != 0x90:
        return None, w
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = sx((immhi << 2) | immlo, 21)
    return (va & ~0xFFF) + (imm << 12), w


print()
print("=" * 78)
print("the two ADRP sites in the variadic log function")
print("=" * 78)
for va in (0x39E600C, 0x39E60C0):
    tgt, w = adrp_target(d, va)
    print("  0x%08x  insn=0x%08x  ADRP target = %s"
          % (va, w or 0, ("0x%x" % tgt) if tgt else "?"))
    if tgt:
        for off_imm in (0x870,):
            slot = tgt + off_imm
            fo = va2off(slot)
            print("        slot 0x%x -> file offset %s" % (slot, fo))
            if fo is not None and fo + 8 <= len(d):
                val = struct.unpack_from("<Q", d, fo)[0]
                print("        stored u64 = 0x%x" % val)
                if val:
                    print("        target code bytes: %s" % d[va2off(val):va2off(val) + 16].hex() if va2off(val) else "?")
