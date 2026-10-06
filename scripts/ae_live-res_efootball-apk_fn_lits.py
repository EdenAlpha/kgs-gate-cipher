"""fn_lits.py <start_va> <end_va> -- every string literal addressed in a code range.

Walks the range and, for each ADRP, recovers the following ADD (or LDR with an
unsigned offset) that lands in loaded data, then prints the NUL-terminated
string at that address together with the instruction that referenced it.

VA -> file offset goes through the program headers.  Identity mapping only
holds inside PT_LOAD #0; using it elsewhere silently reads the wrong bytes.
That is the bug behind the bogus "PLT 0x8b356e0 = __android_log_print" record
(it is `rand`), so every VA read in this file is mapped.

  fn_lits.py 0x6f8ee24 0x6f8f0f0
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

# ---- program headers: VA -> file offset ------------------------------------
e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
LOADS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t = struct.unpack_from("<I", d, o)[0]
    po, pv = struct.unpack_from("<QQ", d, o + 8)
    pm = struct.unpack_from("<Q", d, o + 40)[0]
    if t == 1:
        LOADS.append((po, pv, pm))


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


def cstr(va, n=96):
    """Read a printable NUL-terminated string at a VA, or None."""
    o = va2off(va)
    if o is None or o >= len(d):
        return None
    b = d[o:o + n]
    e = b.find(b"\x00")
    if e <= 0:
        return None
    b = b[:e]
    if not all(32 <= c < 127 for c in b):
        return None
    return b.decode("ascii", "replace")


if len(sys.argv) < 3:
    sys.exit(__doc__)

start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)

# reg -> current ADRP page (before any ADD consumes it)
page = {}
found = []          # (site, target)

for va in range(start, end, 4):
    off = va2off(va)
    if off is None or off + 4 > len(d):
        break
    w = struct.unpack_from("<I", d, off)[0]

    if (w >> 24) & 0x9F == 0x90:                       # ADRP Xd, #imm
        rd = w & 0x1F
        imm = sx(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3), 21)
        page[rd] = (va & ~0xFFF) + (imm << 12)
        continue

    if (w & 0xFF800000) == 0x91000000:                 # ADD Xd, Xn, #imm12
        rd, rn = w & 0x1F, (w >> 5) & 0x1F
        if rn in page:
            imm = (w >> 10) & 0xFFF
            if (w >> 22) & 1:                          # LSL #12 form
                imm <<= 12
            page[rd] = page[rn] + imm
            found.append((va, rd, page[rd]))
        else:
            page.pop(rd, None)
        continue

    if (w & 0xFFC00000) == 0xF9400000:                 # LDR Xt, [Xn, #imm]
        rn = (w >> 5) & 0x1F
        if rn in page:
            found.append((va, rn, page[rn] + ((w >> 10) & 0xFFF) * 8))
        continue

    if (w & 0xFFFFFC00) == 0xAA1F0000:                 # MOV Xd, Xn (ORR XZR)
        rd, rn = w & 0x1F, (w >> 5) & 0x1F
        if rn in page:
            page[rd] = page[rn]
        else:
            page.pop(rd, None)
        continue

    if w == 0xD65F03C0:                                # ret
        break

seen = set()
for site, _, tgt in found:
    s = cstr(tgt)
    if s is None or tgt in seen:
        continue
    seen.add(tgt)
    print("  0x%08x -> 0x%08x  %r" % (site, tgt, s))

if not seen:
    print("  (no string literal addressed in 0x%x..0x%x)" % (start, end))
