#!/usr/bin/env python3
"""Find any store into [reg, #0x6f0..0x734] (non-SP) that sits in a function
which also obtains the config singleton X  (bl 0x7d2bf4c / bl 0x68b4224 /
bl 0x7d376b0).  If none exist, the compiled defaults are authoritative.
"""
import struct, os, sys
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")

GET_S = 0x7D2BF4C        # singleton getter  (S)
GET_X = 0x68B4224        # X = *(S + 0x10)
ACCESS = 0x7D376B0       # X + 0x6f0
BL = 0x94000000


def parse_elf(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    ph = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, o)
        p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", data, o + 8)
        if p_type == 1:
            ph.append((p_offset, p_vaddr, p_filesz, p_flags))
    return ph


def bl_target(pc, w):
    if (w & 0xFC000000) != 0x94000000:
        return None
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return pc + (imm << 2)


def main():
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    LO, HI = 0x6F0, 0x734

    getters = []      # va of each bl to a getter
    stores = []       # (va, offset)

    for po, pv, pf, fl in ph:
        if not (fl & 1):
            continue
        n = pf // 4
        w = np.frombuffer(data, dtype="<u4", count=n, offset=po)

        # ---- BL targets ----
        isbl = (w & np.uint32(0xFC000000)) == np.uint32(0x94000000)
        idx = np.nonzero(isbl)[0]
        if idx.size:
            imm = (w[idx] & np.uint32(0x03FFFFFF)).astype(np.int64)
            neg = (imm & np.uint32(0x02000000)) != 0
            imm = imm - np.where(neg, 0x04000000, 0)
            tgts = (pv + idx.astype(np.int64) * 4) + (imm << 2)
            for i, t in zip(idx, tgts):
                if int(t) in (GET_S, GET_X, ACCESS):
                    getters.append(pv + int(i) * 4)

        # ---- STR/STP with unsigned imm offset in [LO, HI) on non-SP base ----
        # STR Wt, [Xn, #imm12] : 10 111 0 01 00 imm12 Rn Rt  (size=10)  0xB9000000
        # STR Xt, [Xn, #imm12] : 11 111 0 01 00 imm12 Rn Rt             0xF9000000
        # STP Xt,Xt,[Xn,#imm7] : 10 101 0 01 0 imm7 Rn Rt   scaled 8    0xA9000000
        # STP Wt,Wt,[Xn,#imm7] : 00 101 0 01 0 imm7 Rn Rt   scaled 4    0x29000000
        cands = []
        # str w/x (unsigned offset, no writeback, no index)
        for mask, base, scale in ((0xFFC00000, 0xB9000000, 4),
                                  (0xFFC00000, 0xF9000000, 8),
                                  (0xFFC00000, 0x39000000, 1),
                                  (0xFFC00000, 0x39000000, 2)):
            pass
        # do it explicitly for the common ones
        for mask, want in (
            (np.uint32(0xFFC00000), np.uint32(0xB9000000)),   # str wt,[xn,#imm*4]
            (np.uint32(0xFFC00000), np.uint32(0xF9000000)),   # str xt,[xn,#imm*8]
            (np.uint32(0xFFC00000), np.uint32(0x39000000)),   # strb/ldrb-like (strb=0x39000000)
        ):
            m = (w & mask) == want
            ii = np.nonzero(m)[0]
            if ii.size == 0:
                continue
            imm12 = ((w[ii] >> np.uint32(10)) & np.uint32(0xFFF)).astype(np.int64)
            rn = ((w[ii] >> np.uint32(5)) & np.uint32(0x1F))
            scale = {0xB9000000: 4, 0xF9000000: 8, 0x39000000: 1}[int(want)]
            offs = imm12 * scale
            sel = (offs >= LO) & (offs < HI) & (rn != 31)
            for k, off in zip(ii[sel], offs[sel]):
                cands.append((pv + int(k) * 4, int(off)))
        # stp (post-index free, no writeback): 0xA9000000 mask 0xFFC00000 -> imm7*8
        for mask, want, scale in ((np.uint32(0xFFC00000), np.uint32(0xA9000000), 8),
                                  (np.uint32(0xFFC00000), np.uint32(0x29000000), 4)):
            m = (w & mask) == want
            ii = np.nonzero(m)[0]
            if ii.size == 0:
                continue
            imm7 = ((w[ii] >> np.uint32(15)) & np.uint32(0x7F)).astype(np.int64)
            neg = (imm7 & np.uint32(0x40)) != 0
            imm7 = imm7 - np.where(neg, 0x80, 0)
            rn = ((w[ii] >> np.uint32(5)) & np.uint32(0x1F))
            offs = imm7 * scale
            sel = (offs >= LO) & (offs < HI) & (rn != 31)
            for k, off in zip(ii[sel], offs[sel]):
                cands.append((pv + int(k) * 4, int(off)))

        stores.extend(cands)

    getters.sort()
    stores.sort()
    print("X-getter bl sites : %d" % len(getters))
    print("stores into [reg,#0x%x..#0x%x) non-SP : %d" % (LO, HI, len(stores)))

    # a store is "in an X-function" if a getter bl lies within -4000..+4000
    import bisect
    near = []
    for va, off in stores:
        i = bisect.bisect_left(getters, va)
        window = getters[max(0, i - 8):i + 8]
        if any(abs(va - g) <= 4000 for g in window):
            near.append((va, off))
    print("stores within +/-4000 bytes of an X-getter bl : %d" % len(near))
    for va, off in near[:60]:
        print("   store @0x%x   offset=0x%x" % (va, off))


if __name__ == "__main__":
    main()
