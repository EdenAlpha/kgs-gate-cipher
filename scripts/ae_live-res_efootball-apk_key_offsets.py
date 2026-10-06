#!/usr/bin/env python3
"""Within a VA range, report each annotated string literal (config key) and the
   store offsets that follow it, to recover key -> struct-field mapping.
Usage: key_offsets.py <start_hex> <end_hex>
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


def va2off(ph, va):
    for po, pv, pf, _ in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


def off2va(ph, off):
    for po, pv, pf, _ in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


def se(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def adrp_target(insn, pc):
    if ((insn >> 24) & 0x9F) != 0x90:
        return None
    rd = insn & 0x1F
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    return rd, (pc & ~0xFFF) + (se((immhi << 2) | immlo, 21) << 12)


def add_imm(insn, rd):
    if (insn & 0xFF800000) != 0x91000000 or ((insn >> 22) & 3) != 0:
        return None
    if (insn & 0x1F) != rd or ((insn >> 5) & 0x1F) != rd:
        return None
    return (insn >> 10) & 0xFFF


def read_cstr(data, ph, va, maxlen=200):
    o = va2off(ph, va)
    if o is None:
        return None
    e = data.find(b"\x00", o, o + maxlen)
    if e < 0:
        e = o + maxlen
    b = data[o:e]
    if not b or any(c < 0x20 or c > 0x7E for c in b):
        return None
    return b.decode("ascii", "replace")


def main():
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    o = va2off(ph, start)
    buf = data[o:o + (end - start)]
    raw = [struct.unpack_from("<I", buf, i)[0] for i in range(0, len(buf) - 3, 4)]

    # annotate string literals
    lit = {}
    for i, w in enumerate(raw):
        a = adrp_target(w, start + i * 4)
        if a is None:
            continue
        rd, page = a
        for j in range(1, 17):
            if i + j >= len(raw):
                break
            imm = add_imm(raw[i + j], rd)
            if imm is not None:
                s = read_cstr(data, ph, page + imm)
                if s and re.match(r"^[A-Za-z_][A-Za-z0-9_]{3,}$", s):
                    lit[start + i * 4] = s
                break

    out = []
    for pc, s in lit.items():
        # find following sp-relative stores within next 24 insns
        offs = []
        idx = (pc - start) // 4
        for j in range(1, 26):
            if idx + j >= len(raw):
                break
            w = raw[idx + j]
            # str wt, [sp, #imm]  (unsigned, scaled by size)
            if (w & 0x3B000000) == 0x39000000 and ((w >> 24) & 3) == 1 and ((w >> 22) & 3) == 0:
                rn = (w >> 5) & 0x1F
                if rn == 31:
                    size = (w >> 30) & 3
                    bo = ((w >> 10) & 0xFFF) << size
                    offs.append(("sp+0x%x" % bo, "str" + ["b", "h", "w", "x"][size]))
            if start + (idx + j) * 4 in lit:
                break
        out.append((pc, s, offs))

    for pc, s, offs in sorted(out):
        print("0x%x  %-50s  %s" % (pc, s, ", ".join("%s(%s)" % x for x in offs) or "-"))


if __name__ == "__main__":
    main()
