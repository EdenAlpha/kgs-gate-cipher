"""brute_ref.py -- independent check that an address has no reference.

anyref covers PC-relative forms; a jump table may instead hold the address as
a raw 32-bit or 64-bit word (Aarch64 VAs here are < 4 GB, so a table of
32-bit absolute addresses is legal).  This scans both, and prints every
PC-relative branch/ADR in the executable segment whose target matches.
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
    po, pv, pf, pm = (lambda a: (a[0], a[1], a[2], a[3]))(
        struct.unpack_from("<QQQQ", d, o + 16))
    po, pv, filesz, memsz = struct.unpack_from("<QQQQ", d, o + 8)[0:4]
    ph.append((t, fl, po, pv, pf, pm))

print("segments:")
for t, fl, po, pv, pf, pm in ph:
    if t == 1:
        print("  off=0x%-10x va=0x%-10x filesz=0x%-10x memsz=0x%-10x flags=%d"
              % (po, pv, pf, pm, fl))

RX = [(po, pv, pf) for t, fl, po, pv, pf, pm in ph if t == 1 and (fl & 1)][0]
R_OFF, R_VA, R_SZ = RX
print("RX: off=0x%x va=0x%x size=0x%x" % (R_OFF, R_VA, R_SZ))


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


TARGETS = [int(a, 16) for a in sys.argv[1:]]
for T in TARGETS:
    print()
    print("=" * 78)
    print("independent reference scan for 0x%x" % T)
    print("=" * 78)
    hits = []
    for off in range(0, R_SZ, 4):
        w = struct.unpack_from("<I", d, R_OFF + off)[0]
        pc = R_VA + off
        tgt = None
        kind = None
        if (w & 0xFC000000) == 0x14000000:
            tgt, kind = pc + sx(w & 0x3FFFFFF, 26) * 4, "B"
        elif (w & 0xFC000000) == 0x94000000:
            tgt, kind = pc + sx(w & 0x3FFFFFF, 26) * 4, "BL"
        elif (w & 0xFF000010) == 0x54000000:
            tgt, kind = pc + sx((w >> 5) & 0x7FFFF, 19) * 4, "Bcond"
        elif (w & 0xFF000000) in (0x34000000, 0x35000000,
                                  0xB4000000, 0xB5000000):
            tgt, kind = pc + sx((w >> 5) & 0x7FFFF, 19) * 4, "CBZ/CBNZ"
        elif (w & 0xFF000000) in (0x36000000, 0x37000000,
                                  0xB6000000, 0xB7000000):
            tgt, kind = pc + sx((w >> 5) & 0x7FFFF, 19) * 4, "TBZ/TBNZ"
        elif (w >> 24) & 0x9F == 0x10:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            tgt, kind = pc + sx((immhi << 2) | immlo, 21), "ADR"
        if tgt == T:
            hits.append((pc, kind, w))
    print("  PC-relative references: %d" % len(hits))
    for pc, kind, w in hits[:40]:
        print("    %-7s @0x%08x  insn=0x%08x" % (kind, pc, w))

    n8 = n4 = 0
    pat8 = struct.pack("<Q", T)
    i = d.find(pat8)
    while i >= 0:
        n8 += 1
        i = d.find(pat8, i + 1)
    pat4 = struct.pack("<I", T & 0xFFFFFFFF)
    i = d.find(pat4)
    while i >= 0:
        n4 += 1
        i = d.find(pat4, i + 1)
    print("  raw qwords equal to value: %d" % n8)
    print("  raw dwords equal to value: %d" % n4)
