#!/usr/bin/env python3
"""Find every adrp+add reference to a set of absolute VAs and show context."""
import struct, os, sys, re
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


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


def main():
    targets = [int(a, 16) for a in sys.argv[1:]]
    data = open(LIB, "rb").read()
    ph = parse_elf(data)

    # raw value check
    for t in targets:
        o = va2off(ph, t)
        if o is None:
            print("VA 0x%x is NOT in a PT_LOAD (bss/unmapped)" % t)
            continue
        v32 = struct.unpack_from("<I", data, o)[0]
        seg = [(po, pv, pf, fl) for po, pv, pf, fl in ph if pv <= t < pv + pf][0]
        print("VA 0x%x -> fileoff 0x%x  raw_init=0x%08x (%d)  seg va=0x%x flags=0x%x"
              % (t, o, v32, v32, seg[1], seg[3]))

    for t in targets:
        page = t & ~0xFFF
        imm = t & 0xFFF
        print("\n=== refs to 0x%x (page 0x%x + 0x%x) ===" % (t, page, imm))
        hits = []
        for po, pv, pf, fl in ph:
            if not (fl & 1):
                continue
            w = np.frombuffer(data, dtype="<u4", count=pf // 4, offset=po)
            # ADRP
            m = (np.right_shift(w, 24) & np.uint32(0x9F)) == np.uint32(0x90)
            idx = np.nonzero(m)[0]
            if idx.size == 0:
                continue
            immhi = np.right_shift(w[idx], 5) & np.uint32(0x7FFFF)
            immlo = np.right_shift(w[idx], 29) & np.uint32(0x3)
            simm = (immhi << 2) | immlo
            neg = (simm & np.uint32(0x100000)) != 0
            simm = simm.astype(np.int64) - np.where(neg, 0x200000, 0)
            pcs = (pv + idx.astype(np.int64) * 4) & ~0xFFF
            pages = pcs + (simm << 12)
            sel = np.nonzero((pages & ~0xFFF) == (page & ~0xFFF))[0]
            for k in sel:
                i = int(idx[k])
                rd = int(w[i]) & 0x1F
                # look ahead for add reg, reg, #imm12
                for j in range(1, 6):
                    if i + j >= len(w):
                        break
                    nw = int(w[i + j])
                    if (nw & 0xFF800000) == 0x91000000:
                        rn = (nw >> 5) & 0x1F
                        rd2 = nw & 0x1F
                        ad = (nw >> 10) & 0xFFF
                        if rn == rd and ad == imm:
                            hits.append(pv + i * 4)
                        continue
                    if (nw & 0xFF800000) == 0x91000000:
                        continue
                    # ldr/str unsigned offset with same page reg
                    if (nw & 0x3B000000) == 0x39000000 and ((nw >> 24) & 3) == 1:
                        if ((nw >> 5) & 0x1F) == rd:
                            size = (nw >> 30) & 3
                            bo = ((nw >> 10) & 0xFFF) << size
                            if bo == imm:
                                hits.append(pv + i * 4)
                        continue
                    break
        print("   %d hit(s)" % len(hits))
        for h in sorted(set(hits)):
            o = va2off(ph, h)
            buf = data[o - 24:o + 32]
            print("   --- adrp @0x%x ---" % h)
            for x in MD.disasm(buf, h - 24):
                line = "       0x%08x: %-7s %s" % (x.address, x.mnemonic, x.op_str)
                if x.mnemonic in ("mov", "movz", "movk") and "#" in x.op_str:
                    mm = re.search(r"#(0x[0-9a-fA-F]+)", x.op_str)
                    if mm:
                        v = int(mm.group(1), 16)
                        if v > 100:
                            line += "   ; IMM=%d" % v
                print(line)


if __name__ == "__main__":
    main()
