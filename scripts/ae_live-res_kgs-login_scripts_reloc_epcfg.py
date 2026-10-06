#!/usr/bin/env python3
"""Print .rela.dyn entries covering the endpoint-config slots.

If the host slot's relocation addend points at 'pes22-game.cs.konami.net'
(0xa5ed56), the address we've been hitting is definitively correct.
"""
from __future__ import annotations

import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

LO, HI = 0xA4B0000, 0xA4B0300


def main() -> int:
    d = open(SO, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
    e_phnum = struct.unpack_from("<H", d, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        t = struct.unpack_from("<I", d, o)[0]
        po = struct.unpack_from("<Q", d, o + 8)[0]
        pv = struct.unpack_from("<Q", d, o + 16)[0]
        pf = struct.unpack_from("<Q", d, o + 32)[0]
        segs.append((t, po, pv, pf))

    def va2off(va: int):
        for t, po, pv, pf in segs:
            if t == 1 and pv <= va < pv + pf:
                return va - pv + po
        return None

    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
    print("shoff=%#x shnum=%d" % (e_shoff, e_shnum))
    if e_shoff == 0 or e_shnum == 0:
        print("no section headers (stripped)")
        return 1
    # section names
    so = e_shoff + e_shstrndx * e_shentsize
    str_off = struct.unpack_from("<Q", d, so + 24)[0]

    def sname(off: int) -> str:
        end = d.find(b"\x00", str_off + off)
        return d[str_off + off:end].decode("latin1")

    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
            "<IIQQQQIIQQ", d, o)
        nm = sname(sh_name)
        if sh_type in (4, 9) or "rel" in nm.lower() or "APS2" in nm:
            print("relsec %-28s type=%d addr=%#x off=%#x size=%d ent=%d"
                  % (nm, sh_type, sh_addr, sh_offset, sh_size, sh_entsize))
            if sh_entsize in (8, 12, 24):
                for j in range(min(sh_size // sh_entsize, 2000000)):
                    oo = sh_offset + j * sh_entsize
                    if sh_entsize == 24:
                        r_off, r_info, r_add = struct.unpack_from(
                            "<QqQ", d, oo)
                    elif sh_entsize == 12:
                        r_off, r_info = struct.unpack_from("<II", d, oo) \
                            if False else (None, None)
                        continue
                    else:
                        continue
                    if LO <= r_off < HI:
                        print("  reloc @%#x type=%d sym=%d addend=%#x"
                              % (r_off, r_info & 0xFFFFFFFF, r_info >> 32,
                                 r_add & 0xFFFFFFFFFFFFFFFF))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
