#!/usr/bin/env python3
"""Disassemble a contiguous range: python disasm_range.py 0xSTART 0xEND"""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

a = int(sys.argv[1], 16)
b = int(sys.argv[2], 16)
LIM = int(sys.argv[3]) if len(sys.argv) > 3 else 10000


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        f.seek(a - 0x4000)
        code = f.read(b - a)
    n = 0
    for ins in md.disasm(code, a):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
        n += 1
        if n >= LIM:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
