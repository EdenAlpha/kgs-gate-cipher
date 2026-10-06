#!/usr/bin/env python3
"""Read the 16 default config words of the watchdog block (X+0x6f0..0x72f)
from the .rodata quads loaded by the constructor 0x7d36874.

  ldr q0, [0x730000, #0x150] -> X+0x6f0   (words 0..3)
  ldr q1, [0x734000, #0x740] -> X+0x700   (words 4..7)
  ldr q2, [0x739000, #0x9e0] -> X+0x710   (words 8..11)
  ldr q0, [0x73b000, #0x760] -> X+0x720   (words 12..15)

The watchdog resolver (0x6f908d4) reads only X+0x708..0x72c, i.e. words
2..15, and multiplies each by 1000 (ms -> us).
"""
import struct, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")


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


# adrp pages: 0x730000, 0x734000, 0x739000, 0x73b000  (all inside the
# PF_R-only segment 0x0..0x28253b0  => real .rodata, not code)
QUADS = [
    (0x730000 + 0x150, 0x6f0),
    (0x734000 + 0x740, 0x700),
    (0x739000 + 0x9e0, 0x710),
    (0x73b000 + 0x760, 0x720),
]

# resolver slot -> which block word it reads (via accessor +0x18..+0x3c)
# kind 24 -> +0x708        kind 15 -> +0x70c
# kind 30 -> +0x710/+0x714  kind 30 -> +0x718/+0x71c
# kind 27 -> +0x720/+0x724  kind 25 -> +0x728/+0x72c
KIND_BY_OFF = {
    0x708: 24, 0x70c: 15,
    0x710: 30, 0x714: 30, 0x718: 30, 0x71c: 30,
    0x720: 27, 0x724: 27, 0x728: 25, 0x72c: 25,
}


def main():
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    block = {}
    for va, base in QUADS:
        o = va2off(ph, va)
        if o is None:
            print("VA 0x%x not mapped!" % va)
            continue
        words = struct.unpack_from("<4I", data, o)
        raw16 = data[o:o + 16].hex()
        print("quad 0x%08x -> X+0x%03x : %s   [%d, %d, %d, %d]"
              % (va, base, raw16, *words))
        for i, w in enumerate(words):
            block[base + i * 4] = w

    print()
    print("%-8s %-8s %-6s %-14s %-16s %s"
          % ("X_off", "word", "kind", "default_ms", "default_us(x1000)", "s32 signed"))
    for off in sorted(block):
        w = block[off]
        s32 = w - (1 << 32) if w & 0x80000000 else w
        kind = KIND_BY_OFF.get(off, "")
        us = (w * 1000) & 0xFFFFFFFF
        note = ""
        if s32 == -1:
            note = "  <= -1 SENTINEL (unset)"
        if off >= 0x708:
            note += "   [WATCHDOG SLOT]"
        print("0x%04x    %-8d %-6s %-14s %-16s %s%s"
              % (off, w, kind, s32, us, s32, note))


if __name__ == "__main__":
    main()
