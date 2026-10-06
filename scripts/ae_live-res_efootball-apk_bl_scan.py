"""Independent AArch64 B/BL branch-target scanner (no trust in bl_xrefs.py).

Scans every 4-byte-aligned word of the R-X LOAD for B (op 000101) and BL (op 100101)
encodings and reports which of them land on a requested target VA.  Used to settle
whether blocks like 0x6f4f3d8 / 0x6f4f3c4 are genuinely unreferenced (=> vtable
targets or dead code) or whether bl_xrefs.py missed them.
"""
import struct, sys, os
import numpy as np

SO = os.path.join("native", "lib", "arm64-v8a", "libUE4.so")
d = open(SO, "rb").read()

(e_phoff,) = struct.unpack_from("<Q", d, 32)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)

rx = None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", d, o)
    p_off, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
    if p_type == 1 and (p_flags & 1):          # PT_LOAD + PF_X
        rx = (p_off, p_vaddr, p_filesz)
        break

off, base, size = rx
code = np.frombuffer(d, dtype="<u4", count=size // 4, offset=off)
pc = base + np.arange(code.size, dtype=np.int64) * 4

def sext26(x):
    x = x.astype(np.int64)
    return ((x ^ 0x2000000) - 0x2000000)

is_b  = (code & 0xFC000000) == 0x14000000
is_bl = (code & 0xFC000000) == 0x94000000
sel = is_b | is_bl
src = pc[sel]
tgt = pc[sel] + sext26(code[sel] & 0x3FFFFFF) * 4

print("scanned R-X: va=0x%x size=0x%x  instrs=%d  B/BL=%d"
      % (base, size, code.size, src.size))

targets = [int(a, 16) if isinstance(a, str) else a for a in sys.argv[1:]]
for t in targets:
    m = tgt == t
    print("\n== callers of 0x%08x : %d ==" % (t, m.sum()))
    for s in src[m][:20]:
        kind = "BL" if int(code[(s - base) // 4]) >> 26 == 0x25 else "B "
        print("   %s@0x%08x" % (kind, s))
