#!/usr/bin/env python3
"""Find indirect references: raw 8-byte pointers to our target functions,
buried in vtables / dispatch tables / literal pools.

Also finish the BL ascent from the CmdGetServerEnv builder so we can name a
top-level, drivable entry point.
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x6000000

TARGETS = {
    0x7DC7164: "bootstrap_SM",
    0x7DC7165: "bootstrap_SM+1",
    0x7A39EA0: "cmdenv_chain_top",
    0x767EAF0: "cmd_getserverenv_builder",
    0x7D038C8: "http_post_routine",
    0x7D015B0: "http_post_fn",
    0x7CDD628: "http_post_fn2",
}


def main():
    print("scanning whole file for pointer references ...", flush=True)
    with open(SO, "rb") as f:
        blob = f.read()

    hits = defaultdict(list)
    for addr in TARGETS:
        for pat in (struct.pack("<Q", addr), struct.pack("<I", addr)):
            off = 0
            while True:
                i = blob.find(pat, off)
                if i < 0:
                    break
                hits[addr].append((i, len(pat)))
                off = i + 1

    print("\n" + "=" * 74)
    print("POINTER / IMMEDIATE REFERENCES (file offset -> likely section)")
    print("=" * 74)
    for addr, name in TARGETS.items():
        locs = hits.get(addr, [])
        # de-dup 8-byte hits that also matched the 4-byte pattern
        seen = set()
        uniq = []
        for off, w in sorted(locs):
            if any(abs(off - o) < 4 for o, _ in uniq):
                continue
            uniq.append((off, w))
        print(f"\n  {name} {addr:#x}: {len(uniq)} reference(s)")
        for off, w in uniq[:25]:
            where = ".text(code)" if TEXT_OFF <= off < TEXT_OFF + TEXT_SIZE \
                else ("file-offset==vaddr rodata/data"
                      if off < 0x28253C0 else "other")
            print(f"      off {off:#010x}  ({w}B)  {where}")

    # ---------------------------------------------------- BL ascent for env
    print("\n" + "=" * 74)
    print("BL ASCENT from cmd_getserverenv_builder")
    print("=" * 74)
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)

    bl = defaultdict(list)
    n = len(text) // 4
    for idx in range(n):
        insn = struct.unpack_from("<I", text, idx * 4)[0]
        if (insn & 0xFC000000) == 0x94000000:
            imm = insn & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = TEXT_VADDR + idx * 4
            bl[pc + (imm << 2)].append(pc)

    chain = [0x767EAF0, 0x767CEEC, 0x767C0DC, 0x767BDD8, 0x7A39EA0]
    cur = 0x7A39EA0
    for _ in range(8):
        sites = bl.get(cur, [])
        print(f"\n  {cur:#x}  <- {len(sites)} caller(s): "
              f"{', '.join(hex(s) for s in sites[:6])}")
        if not sites:
            print("    (top of chain - reached an entry or an indirect call)")
            break
        cur = sites[0]

    # ---- who calls the http post routine's parents --------------------
    print("\n" + "=" * 74)
    print("BL ASCENT from http_post_routine 0x7d038c8")
    print("=" * 74)
    cur = 0x7D038C8
    for _ in range(8):
        sites = bl.get(cur, [])
        print(f"\n  {cur:#x}  <- {len(sites)} caller(s): "
              f"{', '.join(hex(s) for s in sites[:6])}")
        if not sites:
            break
        cur = sites[0]
    return 0


if __name__ == "__main__":
    sys.exit(main())
