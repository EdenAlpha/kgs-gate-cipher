import struct, os, sys
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
data = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, o)
    p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", data, o + 8)
    if p_type == 1:
        ph.append((p_offset, p_vaddr, p_filesz, p_flags))

T = 0x9C6BDF
tp = T & ~0xFFF
print("target page", hex(tp))

for po, pv, pf, fl in ph:
    if not (fl & 1):
        print("  seg va=0x%x flags=0x%x (NOT EXEC) filesz=0x%x" % (pv, fl, pf))
        continue
    w = np.frombuffer(data, dtype="<u4", count=pf // 4, offset=po)
    m = (np.right_shift(w, 24) & np.uint32(0x9F)) == np.uint32(0x90)
    idx = np.nonzero(m)[0]
    print("  exec seg va=0x%x filesz=0x%x  adrp-candidates=%d" % (pv, pf, idx.size))
    if idx.size == 0:
        continue
    immhi = np.right_shift(w[idx], 5) & np.uint32(0x7FFFF)
    immlo = np.right_shift(w[idx], 29) & np.uint32(0x3)
    simm = (immhi << 2) | immlo
    neg = (simm & np.uint32(0x200000)) != 0
    simm = simm.astype(np.int64) - np.where(neg, 0x400000, 0)
    pcs = (pv + idx.astype(np.int64) * 4) & ~0xFFF
    pages = pcs + (simm << 12)
    sel = np.nonzero((pages & ~0xFFF) == tp)[0]
    print("     matching page count =", sel.size)
    for k in sel[:5]:
        i = int(idx[k])
        print("       adrp@0x%x page=0x%x" % (pv + i * 4, int(pages[k])))
        # inspect following
        for j in range(1, 4):
            nw = int(w[i + j])
            print("         +d%d word=0x%08x  (w&0xFF800000)=0x%08x  Rn=%d" %
                  (j, nw, nw & 0xFF800000, (nw >> 5) & 0x1F))
