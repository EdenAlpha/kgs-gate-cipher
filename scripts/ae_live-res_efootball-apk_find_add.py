#!/usr/bin/env python3
"""Find ADD/SUB (immediate) instructions with a given imm12 and print context.
Usage: find_add.py <imm12_hex> [stride_hex]
"""
import struct, os, sys, re
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


def main():
    imm = int(sys.argv[1], 16)
    ctx = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x30
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    hits = []
    for po, pv, pf, fl in ph:
        if not (fl & 1):
            continue
        chunk = data[po:po + pf]
        n = len(chunk) // 4
        for i in range(n):
            w = struct.unpack_from("<I", chunk, i * 4)[0]
            # ADD/SUB immediate 64-bit, sh=0 : sf=1 op=0 S=0 100010 sh imm12 Rn Rd
            if (w & 0xFF800000) in (0x91000000, 0xD1000000) and ((w >> 22) & 3) == 0:
                if ((w >> 10) & 0xFFF) == imm:
                    hits.append(pv + i * 4)
    print("ADD/SUB imm12=0x%x sites: %d" % (imm, len(hits)))
    for pc in hits:
        off = None
        for po, pv, pf, _ in ph:
            if pv <= pc < pv + pf:
                off = po + (pc - pv)
        print("\n  0x%x:" % pc)
        buf = data[off - 16:off + 16 + ctx]
        for x in MD.disasm(buf, pc - 16):
            line = "      0x%08x: %-8s %s" % (x.address, x.mnemonic, x.op_str)
            if x.mnemonic in ("mov", "movz") and "#" in x.op_str:
                m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", x.op_str)
                if m:
                    v = int(m.group(1), 0)
                    if v > 50:
                        line += "   ; IMM=%d" % v
            print(line)


if __name__ == "__main__":
    main()
