#!/usr/bin/env python3
"""xref2.py -- minimal ELF reader + adrp/add xref finder for arm64 libUE4.so.

Rebuilt 2026-10-10 after temp cleanup destroyed the original.  Interface is
kept identical to the lost original so the committed tool copies keep working:

    from xref2 import Elf, find_xrefs, adrpf, addimm

    e = Elf(path)
    t, f, addr, off, size = e.sec(".rodata")
    raw = e.read(off, size)
    x = find_xrefs(path, [va, ...])   # {va: [pc, ...]}
"""
import struct


def adrpf(w):
    """(rd, page_delta) if `w` is an ADRP, else (None, None)."""
    if w & 0x9F000000 == 0x90000000:
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:            # sign-extend 21-bit
            imm -= 0x200000
        return rd, imm << 12
    return None, None


def addimm(w):
    """(rd, rn, imm12) if `w` is `add xd, xn, #imm` (64-bit, sh=0)."""
    if w & 0xFFC00000 == 0x91000000:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm = (w >> 10) & 0xFFF
        if w & (1 << 22):             # sh=1 -> imm<<12
            imm <<= 12
        return rd, rn, imm
    return None


class Elf:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 2:
            raise ValueError("not an ELF64 file")
        e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
        shoff = e_shoff + e_shstrndx * e_shentsize
        str_off = struct.unpack_from("<Q", d, shoff + 24)[0]
        str_size = struct.unpack_from("<Q", d, shoff + 32)[0]
        shstr = d[str_off:str_off + str_size]
        self.byname = {}
        self.sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            name_off, sh_type = struct.unpack_from("<II", d, off)
            sh_addr = struct.unpack_from("<Q", d, off + 16)[0]
            sh_fileoff = struct.unpack_from("<Q", d, off + 24)[0]
            sh_size = struct.unpack_from("<Q", d, off + 32)[0]
            end = shstr.find(b"\0", name_off)
            name = shstr[name_off:end].decode("latin1")
            rec = (sh_type, 0, name, sh_addr, sh_fileoff, sh_size)
            # layout: (type, flags, name, addr, off, size) -- original interface
            self.byname[name] = rec
            self.sections.append(rec)

    def sec(self, name):
        """(type, flags, name, addr, off, size) for `name`."""
        return self.byname[name]

    def read(self, off, size):
        return self.data[off:off + size]

    def va_read(self, va, size):
        for t, fl, nm, addr, off, sz in self.sections:
            if addr <= va < addr + sz:
                return self.data[off + (va - addr):off + (va - addr) + size]
        return None


def find_xrefs(path, vas):
    """{va: [pc of loading instruction, ...]} for adrp+add pairs in .text."""
    e = Elf(path)
    _, _, _, tv, to, ts = e.sec(".text")
    print("  .text va=%#x off=%#x size=%#x" % (tv, to, ts))
    text = e.read(to, ts)
    want_pages = {}
    for va in vas:
        want_pages.setdefault(va & ~0xFFF, []).append(va)
    out = {va: [] for va in vas}
    n = len(text)
    for i in range(0, n - 16, 4):
        w = struct.unpack_from("<I", text, i)[0]
        rd, delta = adrpf(w)
        if rd is None:
            continue
        pc = tv + i
        page = (pc & ~0xFFF) + delta
        if page not in want_pages:
            continue
        # look ahead up to 5 instructions for `add xd, x{rd}, #imm`
        for k in range(4, 24, 4):
            if i + k >= n:
                break
            w2 = struct.unpack_from("<I", text, i + k)[0]
            add = addimm(w2)
            if add is None:
                continue
            rd2, rn2, imm = add
            if rd2 is not None and rn2 == rd:
                target = page + imm
                if target in out and pc not in out[target]:
                    out[target].append(pc)
                    break
    return out
