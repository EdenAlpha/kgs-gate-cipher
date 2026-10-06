#!/usr/bin/env python3
"""Disassemble the login/bootstrap state machine 0x7dc7164 and extract every
global address it touches (ADRP page + ADD offset), so we can allocate the
singletons it needs and drive it the way the match SM is driven.
"""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

SM = 0x7DC7164
SM_SIZE = 0xCE0
OUT = os.path.join(HERE, "sm_disasm.txt")


def main():
    with open(SO, "rb") as f:
        f.seek(SM - 0x4000)
        code = f.read(SM_SIZE)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False

    lines = []
    for ins in md.disasm(code, SM):
        lines.append(f"{ins.address:#x}: {ins.mnemonic} {ins.op_str}")

    with open(OUT, "w", encoding="utf-8") as g:
        g.write("\n".join(lines))
    print(f"wrote {OUT}  ({len(lines)} instructions)")

    # ---- extract global references -------------------------------------
    print("\n" + "=" * 74)
    print("GLOBAL REFERENCES (adrp page + add/ldr offset)")
    print("=" * 74)

    # re-run with detail to resolve adrp
    md2 = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md2.detail = True
    regs = {}
    refs = {}
    for ins in md2.disasm(code, SM):
        if ins.mnemonic == "adrp":
            ops = ins.operands
            if len(ops) == 2:
                regs[ops[0].reg] = ops[1].imm
        elif ins.mnemonic in ("add", "ldr", "str", "ldrb", "strb",
                              "ldrh", "strh", "ldp", "stp"):
            ops = ins.operands
            for o in ops:
                if o.type == 3:            # mem
                    base = o.mem.base
                    if base in regs:
                        addr = regs[base] + o.mem.disp
                        key = (ins.mnemonic, addr)
                        refs.setdefault(key, []).append(ins.address)

    for (mn, addr), sites in sorted(refs.items(), key=lambda kv: kv[0][1]):
        print(f"  {mn:5s} {addr:#012x}   x{len(sites):2d}  "
              f"e.g. {', '.join(hex(s) for s in sites[:3])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
