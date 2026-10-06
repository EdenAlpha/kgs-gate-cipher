"""near_scan.py <lo> <hi> -- ADRP+ADD sites computing an address in [lo, hi).

`find_addr.py` only matches exact targets.  An initializer that computes a
nearby base and then stores with a large offset (`str x8, [x9, #0x68]`) is
invisible to it, so this reports every ADRP+ADD landing in a window together
with the instructions that follow.

  near_scan.py 0x97a2000 0x97a2400
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


lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
rx_off, rx_va, rx_sz = RX

for va in range(rx_va, rx_va + rx_sz, 4):
    off = va2off(va)
    if off is None:
        break
    w = struct.unpack_from("<I", d, off)[0]
    if (w >> 24) & 0x9F != 0x90:
        continue
    rd = w & 0x1F
    imm = sx(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3), 21)
    page = (va & ~0xFFF) + (imm << 12)

    w2 = struct.unpack_from("<I", d, off + 4)[0]
    tgt = None
    if (w2 & 0xFF800000) == 0x91000000 and ((w2 >> 5) & 0x1F) == rd:
        i = (w2 >> 10) & 0xFFF
        tgt = page + ((i << 12) if (w2 >> 22) & 1 else i)
    elif (w2 & 0xFFC00000) == 0xF9400000 and ((w2 >> 5) & 0x1F) == rd:
        tgt = page + ((w2 >> 10) & 0xFFF) * 8
    if tgt is None or not (lo <= tgt < hi):
        continue

    # dump the next 6 instructions
    tail = []
    for k in range(2, 8):
        w3 = struct.unpack_from("<I", d, off + 4 * k)[0]
        tail.append("0x%08x" % w3)
    print("0x%08x -> 0x%08x   next: %s" % (va, tgt, " ".join(tail)))
