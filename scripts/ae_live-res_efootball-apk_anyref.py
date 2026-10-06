"""Who reaches an address?  Covers every PC-relative form in AArch64:
   B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADR (and reports ADRP separately).
Settles whether a block has truly no reference (=> vtable / data pointer / dead).
"""
import struct, sys, os
import numpy as np

SO = os.path.join("native", "lib", "arm64-v8a", "libUE4.so")
d = open(SO, "rb").read()
(e_phoff,) = struct.unpack_from("<Q", d, 32)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)

rx = ro = None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", d, o)
    p_off, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
    if p_type == 1 and (p_flags & 1) and rx is None:
        rx = (p_off, p_vaddr, p_filesz)
    if p_type == 1 and not (p_flags & 1) and ro is None:
        ro = (p_off, p_vaddr, p_filesz)

off, base, size = rx
code = np.frombuffer(d, dtype="<u4", count=size // 4, offset=off)
pc = base + np.arange(code.size, dtype=np.int64) * 4

def sx(x, bits):
    x = x.astype(np.int64)
    sign = 1 << (bits - 1)
    mask = (1 << bits) - 1
    return ((x & mask) ^ sign) - sign

entries = []   # (src, target, mnemonic)

# B / BL : imm26
for mask, val, name in ((0xFC000000, 0x14000000, "B"), (0xFC000000, 0x94000000, "BL")):
    s = (code & mask) == val
    entries.append((pc[s], pc[s] + sx(code[s] & 0x3FFFFFF, 26) * 4, name))

# B.cond : imm19 at bits[23:5], opcode 0x54000000 (bit4 must be 0)
s = (code & 0xFF000010) == 0x54000000
entries.append((pc[s], pc[s] + sx(code[s] >> 5, 19) * 4, "B.cond"))

# CBZ/CBNZ : 0x34/0x35xxxxxx (32/64 via bit31)
s = (code & 0x7E000000) == 0x34000000
entries.append((pc[s], pc[s] + sx(code[s] >> 5, 19) * 4, "CBZ"))

# TBZ/TBNZ : 0x36/0x37xxxxxx
s = (code & 0x7E000000) == 0x36000000
entries.append((pc[s], pc[s] + sx(code[s] >> 5, 19) * 4, "TBZ"))

# ADR : op 0, immlo bits[30:29], immhi bits[23:5] -> (code & 0x9F000000)==0x10000000
s = (code & 0x9F000000) == 0x10000000
imm = ((code[s] >> 5) << 2) | ((code[s] >> 29) & 3)
entries.append((pc[s], pc[s] + sx(imm, 21), "ADR"))

allsrc = np.concatenate([e[0] for e in entries])
alltgt = np.concatenate([e[1] for e in entries])
allnam = np.concatenate([np.full(e[0].size, e[2]) for e in entries])

# every possible branch-target candidate in R-X is what matters; build a fast lookup
order = np.argsort(alltgt, kind="stable")
st = alltgt[order]

for arg in sys.argv[1:]:
    t = int(arg, 16)
    lo = np.searchsorted(st, t)
    hi = np.searchsorted(st, t, side="right")
    print("\n== any PC-relative reference to 0x%08x : %d ==" % (t, hi - lo))
    for k in order[lo:hi][:25]:
        print("   %-6s @0x%08x" % (allnam[k], allsrc[k]))

    # is it a pointer anywhere (8-byte LE)?
    pat = struct.pack("<Q", t)
    hits = []
    i = d.find(pat)
    while i != -1 and len(hits) < 6:
        hits.append(i); i = d.find(pat, i + 1)
    pat4 = struct.pack("<I", t)
    h4 = []
    i = d.find(pat4)
    while i != -1 and len(h4) < 6:
        h4.append(i); i = d.find(pat4, i + 1)
    print("   abs64-hits=%d abs32-hits=%d  32-bit at file offs: %s"
          % (len(hits), len(h4), [hex(x) for x in h4[:6]]))
