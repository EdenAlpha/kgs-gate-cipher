#!/usr/bin/env python3
"""Full unfiltered disassembly of the config-map bulk loader region
   + resolve ADRP/ADD string keys inline. Output: loader_dump.txt"""
import struct, os, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
OUT = os.path.join(HERE, "loader_dump.txt")

# regions of interest (VA)
RANGES = [
    (0x7c05a00, 0x7c0a200, "CONFIG BULK LOADER (keys -> int32/int64 getters)"),
    (0x7d2a900, 0x7d2ab80, "typed config-map getters 0x7d2a9c0 / 0x7d2aa38"),
    (0x7d15d00, 0x7d16000, "0x7d15db0 site"),
]

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.detail = True


def parse_elf(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    ph = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, o)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<QQQQQQ", data, o + 8)
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


def se(v, b):
    return v - (1 << b) if v & (1 << (b - 1)) else v


def adrp_target(insn, pc):
    if (insn >> 24) & 0x9F != 0x90:
        return None
    rd = insn & 0x1F
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    return rd, (pc & ~0xFFF) + (se((immhi << 2) | immlo, 21) << 12)


def add_imm(insn, rd):
    if (insn & 0xFF800000) != 0x91000000 or ((insn >> 22) & 3) != 0:
        return None
    rn = (insn >> 5) & 0x1F
    if (insn & 0x1F) != rd or rn != rd:
        return None
    return (insn >> 10) & 0xFFF


def read_cstr(data, ph, va, maxlen=96):
    o = va2off(ph, va)
    if o is None:
        return None
    end = data.find(b"\x00", o, o + maxlen)
    if end < 0:
        end = o + maxlen
    b = data[o:end]
    if not b or any(c < 0x20 or c > 0x7e for c in b):
        return None
    return b.decode("ascii", "replace")


def main():
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    out = []

    for start, end, title in RANGES:
        o = va2off(ph, start)
        if o is None:
            out.append("range 0x%x not mapped" % start)
            continue
        buf = data[o:o + (end - start)]
        out.append("\n" + "#" * 96)
        out.append("# %s   [0x%x - 0x%x]" % (title, start, end))
        out.append("#" * 96)
        # first pass: collect adrp/adrp+add string resolutions
        raw = [struct.unpack_from("<I", buf, i)[0] for i in range(0, len(buf) - 3, 4)]
        pc = start
        resolved = {}
        regs = {}
        for i, insn in enumerate(raw):
            a = adrp_target(insn, pc + i * 4)
            if a:
                regs[a[0]] = a[1]
                continue
            add = add_imm(insn, None) if False else None
        # second pass: pair adrp + add within window
        for i, insn in enumerate(raw):
            a = adrp_target(insn, pc + i * 4)
            if a is None:
                continue
            rd, page = a
            for j in range(1, 17):
                if i + j >= len(raw):
                    break
                imm = add_imm(raw[i + j], rd)
                if imm is not None:
                    s = read_cstr(data, ph, page + imm)
                    if s:
                        resolved[pc + i * 4] = s
                    break

        for i, insn in enumerate(raw):
            addr = pc + i * 4
            found = None
            for insn2 in MD.disasm(struct.pack("<I", insn), addr):
                found = insn2
            if found is None:
                out.append("  0x%08x: .word   0x%08x" % (addr, insn))
                continue
            line = "  0x%08x: %-8s %s" % (addr, found.mnemonic, found.op_str)
            if addr in resolved:
                line += '     ; "%s"' % resolved[addr]
            out.append(line)

    open(OUT, "w", encoding="utf-8", errors="replace").write("\n".join(out))
    print("WROTE %s lines=%d" % (OUT, len(out)))


if __name__ == "__main__":
    main()
