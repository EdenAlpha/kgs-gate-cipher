#!/usr/bin/env python3
"""Find inline `add xN,xM,#0x6f0` sites that are followed by a store into
[xN, #byte_offset] with a small offset -> writers of the watchdog config block.
Usage: add6f0_stores.py
"""
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
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    sites = []
    for po, pv, pf, fl in ph:
        if not (fl & 1):
            continue
        w = np.frombuffer(data, dtype="<u4", count=pf // 4, offset=po)
        # ADD (imm) 64-bit sh=0 : 1001000100 imm12 Rn Rd  -> (w & 0xFFC00000)==0x91000000
        m = (w & np.uint32(0xFFC00000)) == np.uint32(0x91000000)
        imm12 = (w >> 10) & np.uint32(0xFFF)
        idx = np.nonzero(m & (imm12 == np.uint32(0x6F0)))[0]
        for i in idx:
            i = int(i)
            rd = int(w[i]) & 0x1F
            for j in range(1, 10):
                if i + j >= len(w):
                    break
                nw = int(w[i + j])
                # STR/LDR unsigned offset
                if (nw & 0x3B000000) == 0x39000000 and ((nw >> 24) & 3) == 1 and ((nw >> 26) & 1) == 0:
                    rn = (nw >> 5) & 0x1F
                    if rn != rd:
                        continue
                    opc = (nw >> 22) & 3
                    size = (nw >> 30) & 3
                    bo = ((nw >> 10) & 0xFFF) << size
                    kind = "STR" if opc == 0 else "LDR"
                    if bo <= 0x40:
                        sites.append((pv + i * 4, pv + (i + j) * 4, kind, bo))
                    break
                if (nw & 0xFF000000) == 0x91000000:
                    continue
                break

    print("inline add #0x6f0 with in-block access: %d" % len(sites))
    st = [s for s in sites if s[2] == "STR"]
    print("  of which STR (writers): %d" % len(st))
    for a, b, k, bo in sorted(st):
        o = va2off(ph, b)
        print("  ADD@0x%x  %s [reg,#0x%x]  (abs +0x%x)" % (a, k, bo, 0x6F0 + bo))
        buf = data[o - 28:o + 8]
        for x in MD.disasm(buf, b - 28):
            line = "      0x%08x: %-8s %s" % (x.address, x.mnemonic, x.op_str)
            if x.mnemonic in ("mov", "movz") and "#" in x.op_str:
                mm = re.search(r"#(0x[0-9a-fA-F]+|\d+)", x.op_str)
                if mm:
                    v = int(mm.group(1), 0)
                    if v > 50:
                        line += "   ; IMM=%d" % v
            print(line)
        print()


if __name__ == "__main__":
    main()
