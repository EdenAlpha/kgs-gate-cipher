"""logcat_sites.py -- who actually calls Android's logging functions?

The earlier census used PLT 0x8b356e0, which is `rand`, so its "187 callers,
5 with a literal, none about the score" was measuring the wrong function.
plt_table.py gives the true stubs:

    0x8b356f0  __android_log_print
    0x8b3af80  __android_log_write
    0x8b3cea0  __android_log_vprint

For every call site we walk backwards collecting ADRP+ADD pairs that land in
read-only data, so the literal arguments (tag / format / message) can be read.

  logcat_sites.py
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

TARGETS = {0x08B356F0: "__android_log_print",
           0x08B3AF80: "__android_log_write",
           0x08B3CEA0: "__android_log_vprint"}

RX_VA, RX_OFF, RX_SZ = 0x28293C0, 0x28253C0, 0x6347D80
DELTA = RX_VA - RX_OFF
RO_LO, RO_HI = 0x0, 0x28253B0          # PT_LOAD #0, read-only, holds .rodata


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


def cstr(va, n=70):
    if not (RO_LO <= va < RO_HI):
        return None
    b = d[va:va + n]
    e = b.find(b"\x00")
    if e <= 0:
        return None
    b = b[:e]
    if not all(32 <= c < 127 or c in (9,) for c in b):
        return None
    return b.decode("ascii", "replace")


def adrps_before(va, k=24):
    """ADRP(+ADD) targets produced in the k instructions before `va`."""
    reg = {}
    start = va - 4 * k
    for a in range(max(start, RX_VA), va, 4):
        w = struct.unpack_from("<I", d, a - DELTA)[0]
        if (w >> 24) & 0x9F == 0x90:                    # ADRP
            rd = w & 0x1F
            imm = sx(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3), 21)
            reg[rd] = (a & ~0xFFF) + (imm << 12)
        elif (w & 0xFF800000) == 0x91000000:            # ADD Xd, Xn, #imm
            rd, rn = w & 0x1F, (w >> 5) & 0x1F
            if rn in reg:
                reg[rd] = reg[rn] + ((w >> 10) & 0xFFF)
            else:
                reg.pop(rd, None)
        elif (w & 0xFFFFFC00) == 0xAA1F0000:            # MOV Xd, Xn (ORR XZR)
            rd, rn = w & 0x1F, (w >> 5) & 0x1F
            if rn in reg:
                reg[rd] = reg[rn]
            else:
                reg.pop(rd, None)
    return sorted(set(reg.values()), reverse=True)


sites = {t: [] for t in TARGETS}
for va in range(RX_VA, RX_VA + RX_SZ, 4):
    w = struct.unpack_from("<I", d, va - DELTA)[0]
    if (w & 0xFC000000) != 0x94000000:
        continue
    imm = w & 0x3FFFFFF
    if imm >= 0x2000000:
        imm -= 0x4000000
    tgt = va + imm * 4
    if tgt in TARGETS:
        sites[tgt].append(va)

total = 0
for tgt, name in TARGETS.items():
    ss = sites[tgt]
    total += len(ss)
    print("=" * 78)
    print("%s  PLT 0x%x   call sites: %d" % (name, tgt, len(ss)))
    print("=" * 78)
    with_lit = 0
    for va in ss:
        cands = [cstr(x) for x in adrps_before(va)]
        cands = [c for c in cands if c]
        if cands:
            with_lit += 1
            print("  0x%08x  %s" % (va, " | ".join(cands[:4])))
    print("  sites with at least one readable literal: %d / %d"
          % (with_lit, len(ss)))
    print()

print("TOTAL logcat call sites: %d" % total)
