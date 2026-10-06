#!/usr/bin/env python3
"""1. validate the .rela.dyn parse: do ANY known .dynsym function starts show
   up as addends?  (if zero, the parse/section assumption is wrong)
2. scan unconditional B (tail-call) targets for our mystery functions
3. scan CBZ/CBNZ/TBZ/B.cond targets that land exactly on a function start
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict

from elftools.elf.elffile import ELFFile

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

KEYS = [0x7DC7164, 0x7A39B0C, 0x767CECC, 0x7D038C8, 0x7D017DC,
        0x7CE7070, 0x7D0BDA8, 0x7D157F8, 0x767EAF0]


def load_fde_starts():
    p = os.path.join(HERE, "funcs_eh.txt")
    out = set()
    with open(p, encoding="utf-8") as f:
        for line in f:
            a = int(line.split()[0], 16)
            out.add(a)
    return out


def main():
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        dyn = elf.get_section_by_name(".dynsym")
        dyn_starts = {s["st_value"] for s in dyn.iter_symbols()
                      if s.name and s["st_size"] > 0}

        rela = elf.get_section_by_name(".rela.dyn")
        raw = rela.data()
        addends = set()
        for off in range(0, len(raw) - 24, 24):
            _o, _i, a = struct.unpack_from("<QQq", raw, off)
            addends.add(a)

        print("=" * 74)
        print("(1) .rela.dyn parse validation")
        print("=" * 74)
        print(f"  distinct addends: {len(addends):,}")
        print(f"  dynsym fn starts found as addends: "
              f"{len(dyn_starts & addends):,} / {len(dyn_starts):,}")
        # also: what do addends look like at all?
        in_text = sum(1 for a in addends
                      if TEXT_VADDR <= a < TEXT_VADDR + TEXT_SIZE)
        print(f"  addends inside .text: {in_text:,}")
        print(f"  are OUR keys addends? "
              f"{[hex(k) for k in KEYS if k in addends] or 'none'}")

    print("\n" + "=" * 74)
    print("(2)/(3) B and conditional-branch targets in .text")
    print("=" * 74)
    fde = load_fde_starts()
    print(f"  FDE starts loaded: {len(fde):,}")

    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)

    want = set(KEYS)
    hits = defaultdict(dict)
    branches = defaultdict(int)

    n = len(text) // 4
    for idx in range(n):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        pc = TEXT_VADDR + idx * 4

        # ---- unconditional B ----
        if (i & 0xFC000000) == 0x14000000:
            imm = i & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            t = pc + (imm << 2)
            branches["B"] += 1
            if t in want:
                hits[t].setdefault("B", []).append(pc)
            continue

        # ---- CBZ / CBNZ (64 and 32 bit) ----
        if (i & 0x7E000000) == 0x34000000:
            imm = ((i >> 5) & 0x7FFFF)
            if imm & (1 << 18):
                imm -= 1 << 19
            t = pc + (imm << 2)
            branches["CBZ"] += 1
            if t in want:
                hits[t].setdefault("CBZ", []).append(pc)
            continue
        # ---- TBZ / TBNZ ----
        if (i & 0x7E000000) == 0x36000000:
            imm = ((i >> 5) & 0x3FFF)
            if imm & (1 << 13):
                imm -= 1 << 14
            t = pc + (imm << 2)
            branches["TBZ"] += 1
            if t in want:
                hits[t].setdefault("TBZ", []).append(pc)
            continue
        # ---- B.cond ----
        if (i & 0xFF000010) == 0x54000000:
            imm = ((i >> 5) & 0x7FFFF)
            if imm & (1 << 18):
                imm -= 1 << 19
            t = pc + (imm << 2)
            branches["Bcond"] += 1
            if t in want:
                hits[t].setdefault("Bcond", []).append(pc)
            continue

    print(f"  branch counts: {dict(branches)}")
    print()
    for k in KEYS:
        h = hits.get(k, {})
        if not h:
            print(f"  {k:#x}: no B/CBZ/TBZ/Bcond target")
            continue
        print(f"  {k:#x}:")
        for kind, sites in h.items():
            print(f"      {kind}: {len(sites)}  "
                  f"{', '.join(hex(s) for s in sites[:8])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
