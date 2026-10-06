#!/usr/bin/env python3
"""For each `bl 0x7d17d24` site (the game's snprintf wrapper), walk backwards
to the ADRP+ADD that materialises the format string and print it.

These format strings ARE the request bodies the game sends, so this is the
quickest way to tell one builder from another.
"""
import struct
import sys

SO = r'apk_lab\libUE4.so'
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0

data = open(SO, 'rb').read()


def insn(a):
    off = TEXT_OFF + (a - TEXT_V)
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from('<I', data, off)[0]


def adrp(w, a):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (w & 31, (a & ~0xFFF) + (imm << 12))


def add_imm(w):
    if (w & 0xFFC00000) != 0x91000000:
        return None
    return (w & 31), ((w >> 5) & 31), ((w >> 10) & 0xFFF)


def fmt_for(site, maxback=64):
    for back in range(4, maxback):
        a = site - back * 4
        w = insn(a)
        r = adrp(w, a)
        if not r:
            continue
        rd, pg = r
        for k in range(1, 8):
            ai = add_imm(insn(a + k * 4))
            if ai and ai[1] == rd:
                addr = pg + ai[2]
                if 0 < addr < len(data):
                    s = data[addr:addr + 160].split(b'\0')[0]
                    try:
                        t = s.decode('utf-8')
                    except Exception:
                        t = repr(s)
                    if len(t) > 3:
                        return addr, t
    return None, None


def main():
    sites = [int(x, 16) for x in sys.argv[1:]]
    for s in sites:
        a, t = fmt_for(s)
        if t is None:
            print(f'  {s:#x}  <no string>')
        else:
            print(f'  {s:#x}  @{a:#x}\n        {t[:150]}')


if __name__ == '__main__':
    main()
