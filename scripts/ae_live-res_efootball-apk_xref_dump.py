#!/usr/bin/env python3
"""Find code xrefs to given literal strings; dump containing function fully.
Usage: xref_dump.py <substring> [substring ...]"""
import struct, os, re, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
OUT = os.path.join(HERE, "xref_dump.txt")

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
    if not b or any(c < 0x20 or c > 0x7e for c in b):
        return None
    return b.decode("ascii", "replace")


def main():
    subs = sys.argv[1:] or ["MatchOnlineWatchDog"]
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    out = []

    # locate literals
    targets = {}
    for sub in subs:
        b = sub.encode()
        s = 0
        while True:
            i = data.find(b, s)
            if i < 0:
                break
            s = i + 1
            # expand to whole C string
            st = i
            while st > 0 and data[st - 1] != 0 and 0x20 <= data[st - 1] <= 0x7e:
                st -= 1
            e = data.find(b"\x00", i)
            full = data[st:e if e > 0 else i + len(b)]
            va = off2va(ph, st)
            if va is not None:
                targets[va] = full.decode("ascii", "replace")
    out.append("literals found: %d" % len(targets))
    for va, t in targets.items():
        out.append("  0x%x  %s" % (va, t))

    if not targets:
        open(OUT, "w").write("\n".join(out))
        print("WROTE", OUT, "(no literals)")
        return

    ex = [(po, pv, pf) for po, pv, pf, fl in ph if fl & 1]
    xrefs = []
    for po, pv, pf in ex:
        chunk = data[po:po + pf]
        n = len(chunk) // 4
        for i in range(n):
            w = struct.unpack_from("<I", chunk, i * 4)[0]
            a = adrp_target(w, pv + i * 4)
            if a is None:
                continue
            rd, page = a
            for j in range(1, 17):
                if i + j >= n:
                    break
                imm = add_imm(struct.unpack_from("<I", chunk, (i + j) * 4)[0], rd)
                if imm is not None:
                    if (page + imm) in targets:
                        xrefs.append(pv + i * 4)
                    break
    out.append("\nxrefs: %d" % len(xrefs))
    for pc in xrefs:
        out.append("  0x%x" % pc)

    def find_prologue(va, limit=0x4000):
        o = va2off(ph, va)
        if o is None:
            return va
        start = max(0, o - limit)
        off = o
        candidate = None
        while off >= start:
            w = struct.unpack_from("<I", data, off)[0]
            if ((w & 0xFFC07FFF) == 0xA9807BFD) and (((w >> 15) & 0x7F) >= 0x40):
                return off2va(ph, off)
            if candidate is None and (w & 0xFFC003FF) == 0xD10003FF and ((w >> 10) & 0xFFF) >= 0x10:
                candidate = off2va(ph, off)
            if w == 0xD65F03C0:
                break
            off -= 4
        return candidate if candidate is not None else va - 0x100

    seen = set()
    for pc in xrefs:
        fn = find_prologue(pc)
        if fn in seen:
            continue
        seen.add(fn)
        o = va2off(ph, fn)
        buf = data[o:o + 0x1400]
        raw = [struct.unpack_from("<I", buf, i)[0] for i in range(0, len(buf) - 3, 4)]
        ann = {}
        for i, w in enumerate(raw):
            a = adrp_target(w, fn + i * 4)
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
                        ann[fn + i * 4] = s
                    break
        out.append("\n" + "#" * 100)
        out.append("# xref=0x%x  func@0x%x" % (pc, fn))
        out.append("#" * 100)
        for i, w in enumerate(raw):
            addr = fn + i * 4
            d = None
            for x in MD.disasm(struct.pack("<I", w), addr):
                d = x
            if d is None:
                line = "  0x%08x: .word   0x%08x" % (addr, w)
            else:
                line = "  0x%08x: %-8s %s" % (addr, d.mnemonic, d.op_str)
                if addr in ann:
                    line += '   ; "%s"' % ann[addr]
                if d.mnemonic in ("mov", "movz") and "#" in d.op_str:
                    m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", d.op_str)
                    if m:
                        try:
                            v = int(m.group(1), 0)
                            if 60 < v < 200000000:
                                line += "   ; IMM=%d" % v
                        except Exception:
                            pass
            out.append(line)
            if addr >= fn and (w & 0xFFFFFFFF) == 0xD65F03C0 and addr > fn + 0x40:
                break
            if i > 900:
                break
    open(OUT, "w", encoding="utf-8", errors="replace").write("\n".join(out))
    print("WROTE %s lines=%d" % (OUT, len(out)))


if __name__ == "__main__":
    main()
