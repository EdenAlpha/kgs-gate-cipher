#!/usr/bin/env python3
"""List every string literal a function references.

Walks the function body for ADRP+ADD (and ADR+ADD) materialisers, resolves
them, and prints the ones that land in .rodata as printable C strings.
"""
import struct
import sys

SO = r'apk_lab\libUE4.so'
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0

data = open(SO, 'rb').read()
RODATA_HI = 0x0C400000


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


def adr(w, a):
    if (w & 0x9F000000) != 0x10000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (w & 31, a + imm)


def add_imm(w):
    if (w & 0xFFC00000) != 0x91000000:
        return None
    return (w & 31), ((w >> 5) & 31), ((w >> 10) & 0xFFF)


def strings_in(fn_lo, fn_hi):
    out = []
    seen = set()
    a = fn_lo
    while a < fn_hi:
        w = insn(a)
        base = adrp(w, a) or adr(w, a)
        if base:
            rd, pg = base
            for k in range(1, 9):
                ai = add_imm(insn(a + k * 4))
                if ai and ai[1] == rd:
                    addr = pg + ai[2]
                    if 0 < addr < len(data) and addr not in seen:
                        s = data[addr:addr + 200].split(b'\0')[0]
                        if s and all(32 <= c < 127 or c in (9,) for c in s):
                            seen.add(addr)
                            out.append((addr, s.decode('latin1')))
                    break
        a += 4
    return out


def main():
    lo = int(sys.argv[1], 16)
    hi = int(sys.argv[2], 16)
    print(f'--- function {lo:#x}..{hi:#x} ---')
    for addr, s in strings_in(lo, hi):
        print(f'  {addr:#x}  {s[:140]}')


if __name__ == '__main__':
    main()
