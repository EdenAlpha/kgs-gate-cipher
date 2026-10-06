#!/usr/bin/env python3
"""Catalog every string passed to a 'set reason/message' setter.

Found by inspecting OnlineModeTaskMatchSession.cpp's disconnect handler:

    add  x0, x21, #0x200          ; destination member
    adrp x1, #0x... ; "<reason>"  ; literal
    add  x1, x1, #0x...
    mov  w2, #<len>
    bl   #0x2f15088               ; setter(dest, cstr, len)

Scanning every BL to that setter in .text and resolving the literal in each
caller's preamble yields the full catalogue of reason strings the game can
report, with their source file (from the log-path adrp when present).

Usage: reason_catalog.py [setter_va_hex]
"""
import struct
import os
import re
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

SETTER = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x2F15088
BACK = 14          # instructions to scan backwards for the literal
FORWARD_FOR_FILE = 40


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


def find_bl_sites(data, ph, target):
    sites = []
    for po, pv, pf, fl in ph:
        if not (fl & 1):
            continue
        w = np.frombuffer(data, dtype="<u4", count=pf // 4, offset=po)
        s = (w & np.uint32(0xFC000000)) == np.uint32(0x94000000)
        idx = np.nonzero(s)[0]
        if idx.size == 0:
            continue
        imm = (w[idx] & np.uint32(0x3FFFFFF)).astype(np.int64)
        sign = np.where(imm & 0x2000000, imm - 0x4000000, imm)
        tgt = (pv + idx.astype(np.int64) * 4) + sign * 4
        sel = np.nonzero(tgt == target)[0]
        sites.extend(int(pv + int(idx[k]) * 4) for k in sel)
    return sorted(set(sites))


def va2off(ph, va):
    for po, pv, pf, _ in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


def disasm(data, ph, va, n):
    o = va2off(ph, va)
    if o is None:
        return []
    buf = data[o:o + 4 * n]
    return list(MD.disasm(buf, va))


def resolve_literal(data, ph, site):
    """Walk backwards from `site`; return (string, len_field) if found."""
    o = va2off(ph, site)
    if o is None:
        return None, None
    start = o - 4 * BACK
    if start < 0:
        start = 0
    ins = list(MD.disasm(data[start:o + 4], site - (o - start)))
    regs = {}
    length = None
    result = None
    for x in ins:
        m = re.match(r"x(\d+), x\1, #0x([0-9a-f]+)$", x.op_str)
        if x.mnemonic == "adrp":
            mm = re.match(r"x(\d+), #0x([0-9a-f]+)", x.op_str)
            if mm:
                regs[int(mm.group(1))] = int(mm.group(2), 16)
        elif x.mnemonic == "add" and m:
            r = int(m.group(1))
            if r in regs:
                regs[r] += int(m.group(2), 16)
        elif x.mnemonic == "mov":
            mm = re.match(r"w(\d+), #0x([0-9a-f]+)$", x.op_str)
            if mm and int(mm.group(1)) == 2:
                length = int(mm.group(2), 16)
        elif x.mnemonic == "bl":
            pass
    # x1 holds the literal in the observed pattern
    va = regs.get(1)
    if va is None:
        return None, length
    lo = va2off(ph, va)
    if lo is None:
        return None, length
    s = data[lo:lo + 400].split(b"\0", 1)[0]
    return s.decode("latin-1", "replace"), length


def find_source_file(data, ph, site, span=FORWARD_FOR_FILE):
    """Look ahead for the G:\\PES22HC ... .cpp path used by the log call."""
    o = va2off(ph, site)
    if o is None:
        return None
    for x in MD.disasm(data[o:o + 4 * span], site):
        if x.mnemonic != "adrp":
            continue
        mm = re.match(r"x(\d+), #0x([0-9a-f]+)", x.op_str)
        if not mm:
            continue
        page = int(mm.group(2), 16)
        # try lo12 from the following add
        nxt = list(MD.disasm(data[o + 4: o + 4 * 6], site + 4))
        for y in nxt:
            m2 = re.match(r"x%s, x%s, #0x([0-9a-f]+)$" % (mm.group(1), mm.group(1)),
                          y.op_str)
            if m2 and y.mnemonic == "add":
                lo = va2off(ph, page + int(m2.group(1), 16))
                if lo is None:
                    break
                s = data[lo:lo + 300].split(b"\0", 1)[0]
                if b"PES22HC" in s or s.endswith(b".cpp"):
                    return s.decode("latin-1", "replace")
                break
    return None


def main():
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    sites = find_bl_sites(data, ph, SETTER)
    print("[setter 0x%x] %d call sites\n" % (SETTER, len(sites)))
    for s in sites:
        lit, ln = resolve_literal(data, ph, s)
        src = find_source_file(data, ph, s)
        print("  0x%08x  len=%-4s %r" % (s, ln, lit))
        if src:
            print("        file: %s" % src)


if __name__ == "__main__":
    main()
