#!/usr/bin/env python3
"""Find who HOLDS a pointer to our target functions.

Two mechanisms, both needed for an aarch64 RELA PIE:
  1. .rela.dyn  R_AARCH64_RELATIVE addends -> static pointer tables
  2. ADRP+ADD / ADR materialising the address -> BLR (indirect calls)
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

KEYS = {
    0x7DC7164: "bootstrap_SM",
    0x7A39B0C: "cmdenv_chain_top_fn",
    0x767CECC: "cmdenv_dispatcher_fn",
    0x7D038C8: "http_post_routine",
    0x7D017DC: "http_post_parent_fn",
    0x7CE7070: "http_post_grandparent",
    0x7D0BDA8: "gateinfo_parent_fn",
    0x7D157F8: "http_post_alt_fn",
    0x767EAF0: "cmd_getserverenv_builder",
}


def section_of(elf, addr):
    for s in elf.iter_sections():
        if s["sh_addr"] and s["sh_addr"] <= addr < s["sh_addr"] + s.data_size:
            return s.name
    return "?"


def main():
    with open(SO, "rb") as f:
        elf = ELFFile(f)

        print("=" * 74)
        print("1) .rela.dyn addend references (static pointer tables)")
        print("=" * 74)
        rela = elf.get_section_by_name(".rela.dyn")
        found = defaultdict(list)
        n = 0
        if rela is not None:
            # pyelftools hands back a bare Section here -> parse Elf64_Rela
            # (r_offset 8, r_info 8, r_addend 8) ourselves.
            raw = rela.data()
            for off in range(0, len(raw) - 24, 24):
                r_offset, _info, r_addend = struct.unpack_from(
                    "<QQq", raw, off)
                n += 1
                if r_addend in KEYS:
                    found[r_addend].append(r_offset)
        print(f"  scanned {n:,} relocations")
        for addr, name in KEYS.items():
            offs = found.get(addr, [])
            print(f"\n  {name} {addr:#x}: {len(offs)} relocation(s)")
            for o in offs[:20]:
                print(f"      stored at {o:#x}  section={section_of(elf, o)}")
            if not offs:
                print("      (none)")

        print("\n" + "=" * 74)
        print("2) ADRP+ADD / ADR materialisation in .text (indirect BLR)")
        print("=" * 74)

    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)

    def imm_hi(i):
        v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
        if v & (1 << 20):
            v -= 1 << 21
        return v << 12

    def imm12(i):
        v = (i >> 10) & 0xFFF
        if v & (1 << 11):
            v -= 1 << 12
        return v

    want = set(KEYS)
    hits = defaultdict(list)
    last = (None, None)
    n = len(text) // 4
    for idx in range(n):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        pc = TEXT_VADDR + idx * 4
        if (i & 0x9F000000) == 0x90000000:            # ADRP
            last = (i & 0x1F, (pc & ~0xFFF) + imm_hi(i))
            continue
        if (i & 0x9F000000) == 0x10000000:            # ADR
            v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
            if v & (1 << 20):
                v -= 1 << 21
            t = pc + v
            if t in want:
                hits[t].append((pc, "ADR"))
            continue
        if (i & 0xFFC00000) == 0x91000000:            # ADD imm
            rn = (i >> 5) & 0x1F
            if last[0] == rn:
                t = last[1] + imm12(i)
                if t in want:
                    hits[t].append((pc, "ADRP+ADD"))

    for addr, name in KEYS.items():
        h = hits.get(addr, [])
        print(f"\n  {name} {addr:#x}: {len(h)} materialisation(s)")
        for s, kind in h[:20]:
            print(f"      {s:#x}  {kind}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
