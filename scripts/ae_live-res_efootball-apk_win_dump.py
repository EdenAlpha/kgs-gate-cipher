#!/usr/bin/env python3
"""Unfiltered dump of an arbitrary VA window with string annotation."""
import struct, os, re, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.detail = True


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
    if (insn & 0x1F) != rd or ((insn >> 5) & 0x1F) != rd:
        return None
    return (insn >> 10) & 0xFFF


def read_cstr(data, ph, va, maxlen=110):
    o = va2off(ph, va)
    if o is None:
        return None
    e = data.find(b"\x00", o, o + maxlen)
    if e < 0:
        e = o + maxlen
    b = data[o:e]
    if not b or any(c < 0x20 or c > 0x7e for c in b):
        return None
    return b.decode("ascii", "replace")


def dump(va_start, va_end, data, ph, out, title=""):
    o = va2off(ph, va_start)
    if o is None:
        out.append("unmapped 0x%x" % va_start)
        return
    buf = data[o:o + (va_end - va_start)]
    raw = [struct.unpack_from("<I", buf, i)[0] for i in range(0, len(buf) - 3, 4)]
    ann = {}
    for i, w in enumerate(raw):
        a = adrp_target(w, va_start + i * 4)
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
                    ann[va_start + i * 4] = s
                break
    out.append("\n" + "#" * 96)
    out.append("# %s  [0x%x - 0x%x]" % (title, va_start, va_end))
    out.append("#" * 96)
    for i, w in enumerate(raw):
        addr = va_start + i * 4
        d = None
        for x in MD.disasm(struct.pack("<I", w), addr):
            d = x
        if d is None:
            line = "  0x%08x: .word   0x%08x" % (addr, w)
        else:
            line = "  0x%08x: %-8s %s" % (addr, d.mnemonic, d.op_str)
            if addr in ann:
                line += '   ; "%s"' % ann[addr]
            if d.mnemonic in ("mov", "movz", "movk") and "#" in d.op_str:
                m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", d.op_str)
                if m:
                    try:
                        v = int(m.group(1), 0)
                        if 60 < v < 200000000 and d.mnemonic != "movk":
                            line += "   ; IMM=%d" % v
                    except Exception:
                        pass
        out.append(line)


def main():
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    out = []
    args = sys.argv[1:]
    if args:
        for i in range(0, len(args), 2):
            a = int(args[i], 16)
            b = int(args[i + 1], 16)
            dump(a, b, data, ph, out, args[i] + ".." + args[i + 1])
    else:
        dump(0x7c0ac00, 0x7c0b380, data, ph, out, "before MatchAbortTimerCoefficient reader")
        dump(0x7c09600, 0x7c09a00, data, ph, out, "before KeepAliveTimerUs reader")
    path = os.path.join(HERE, sys.argv[0].split(os.sep)[-1].replace("win_dump.py", "win_dump.txt"))
    if not path.endswith(".txt"):
        path = os.path.join(HERE, "win_dump.txt")
    open(path, "w", encoding="utf-8", errors="replace").write("\n".join(out))
    print("WROTE %s lines=%d" % (path, len(out)))


if __name__ == "__main__":
    main()
