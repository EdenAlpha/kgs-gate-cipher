#!/usr/bin/env python3
"""Find STR/LDR/STP sites whose *byte* offset falls in a range, with the
   preceding instructions (to see where immediates come from).
Usage: find_stores.py <lo_hex> <hi_hex>
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
    lo = int(sys.argv[1], 16)
    hi = int(sys.argv[2], 16)
    stroly = "str" in sys.argv[3:]
    nosp = "nosp" in sys.argv[3:]
    data = open(LIB, "rb").read()
    ph = parse_elf(data)

    hits = []  # (pc, byte_off, kind)
    for po, pv, pf, fl in ph:
        if not (fl & 1):
            continue
        chunk = data[po:po + pf]
        n = len(chunk) // 4
        for i in range(n):
            w = struct.unpack_from("<I", chunk, i * 4)[0]
            pc = pv + i * 4
            # STR/LDR unsigned immediate: size(31-30) 111 V 01 opc(23-22) imm12 Rn Rt
            if (w & 0x3B000000) == 0x39000000 and ((w >> 26) & 1) == 0 and ((w >> 24) & 3) == 1 \
               and ((w >> 23) & 1) == 0:
                opc = (w >> 22) & 3
                is_store = (opc == 0)             # STR* unsigned offset
                size = (w >> 30) & 3
                imm12 = (w >> 10) & 0xFFF
                rn = (w >> 5) & 0x1F
                bo = imm12 << size
                if stroly and not is_store:
                    continue
                if nosp and rn == 31:
                    continue
                if "imm" in sys.argv[3:] and i > 0:
                    prev = chunk[(i - 1) * 4:i * 4]
                    pd = None
                    for d in MD.disasm(prev, pc - 4):
                        pd = d
                    if pd is None or pd.mnemonic not in ("mov", "movz", "movn", "movk", "orr", "and"):
                        continue
                    if "#" not in pd.op_str:
                        continue
                if lo <= bo <= hi:
                    hits.append((pc, bo, "str" if is_store else "ldr"))
            # STP/LDP unsigned immediate (bits 31-23 = size 101 x 100 for 64-bit? )
            # STP w (32-bit, no writeback): 0010 1001 00 imm7 -> 0x29000000
            # STP x: 1010 1001 00 imm7 -> 0xA9000000 ; LDP x: 0xA9...
            if (w & 0x3B800000) in (0x29000000, 0x28800000, 0x29800000, 0x28000000):
                size = (w >> 30) & 3
                imm7 = (w >> 15) & 0x7F
                if imm7 >= 64:
                    imm7 -= 128
                bo = imm7 << size
                if lo <= bo <= hi:
                    hits.append((pc, bo, "stp/ldp"))

    print("store sites into [0x%x..0x%x]: %d" % (lo, hi, len(hits)))
    byoff = {}
    for pc, imm, k in hits:
        byoff.setdefault(imm, []).append((pc, k))
    for imm in sorted(byoff):
        print("\n-- byte offset 0x%x  (%d sites)" % (imm, len(byoff[imm])))
        for pc, k in byoff[imm][:40]:
            off = None
            for po, pv, pf, _ in ph:
                if pv <= pc < pv + pf:
                    off = po + (pc - pv)
            buf = data[off - 24:off + 8]
            print("   %s 0x%x:" % (k, pc))
            for x in MD.disasm(buf, pc - 24):
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
