#!/usr/bin/env python3
"""Find code xrefs (adrp+add) to literal string VAs and report callers.
Usage: str_xrefs.py <va_hex> [<va_hex> ...]
"""
import struct, os, sys
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")


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


def va2off(ph, va):
    for po, pv, pf, _ in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


def se(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def build(data, ph):
    segs = []
    for po, pv, pf, fl in ph:
        if not (fl & 1):
            continue
        w = np.frombuffer(data, dtype="<u4", count=pf // 4, offset=po)
        segs.append((pv, w))
    return segs


def main():
    targets = [int(a, 16) for a in sys.argv[1:]]
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    segs = build(data, ph)

    for t in targets:
        hits = []
        tp = t & ~0xFFF
        for base, w in segs:
            # ADRP: bits 28-24 == 10000 -> (w>>24)&0x9F == 0x90
            m = (np.right_shift(w, 24) & np.uint32(0x9F)) == np.uint32(0x90)
            idx = np.nonzero(m)[0]
            if idx.size == 0:
                continue
            immhi = np.right_shift(w[idx], 5) & np.uint32(0x7FFFF)
            immlo = np.right_shift(w[idx], 29) & np.uint32(0x3)
            simm = (immhi << 2) | immlo
            neg = (simm & np.uint32(0x100000)) != 0
            simm = simm.astype(np.int64) - np.where(neg, 0x200000, 0)
            pcs = (base + idx.astype(np.int64) * 4) & ~0xFFF
            pages = pcs + (simm << 12)
            sel = np.nonzero((pages & ~0xFFF) == (tp & ~0xFFF))[0]
            for k in sel:
                i = int(idx[k])
                ww = int(w[i])
                rd = ww & 0x1F
                page = int(pages[k])
                for j in range(1, 24):
                    if i + j >= len(w):
                        break
                    nw = int(w[i + j])
                    if ((nw >> 24) & 0x9F) == 0x90:
                        break
                    if (nw & 0xFF800000) != 0x91000000 or ((nw >> 22) & 3) != 0:
                        continue
                    if (nw >> 5) & 0x1F != rd:
                        continue
                    if page + ((nw >> 10) & 0xFFF) == t:
                        hits.append(base + i * 4)
                    break
        print("=== xrefs to 0x%x : %d" % (t, len(hits)))
        for h in hits:
            print("   xref=0x%x" % h)


if __name__ == "__main__":
    main()
