#!/usr/bin/env python3
"""Disassemble the sender 0x7d03b68 and its 'begin' method 0x7d044b0."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

FNS = [(0x7D03B68, 0x140), (0x7D044B0, 0x200)]


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for a, size in FNS:
            f.seek(a - 0x4000)
            code = f.read(size)
            print("=" * 74)
            print(f"{a:#x}  (size {size:#x})")
            print("=" * 74)
            for ins in md.disasm(code, a):
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
