#!/usr/bin/env python3
"""Disassemble a list of addresses (small windows) to identify curl funcs."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

ADDRS = [int(a, 16) for a in sys.argv[1:]] or [0x68788B4, 0x68788C4]


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for a in ADDRS:
            f.seek(a - 0x4000)
            code = f.read(0x60)
            print("=" * 60)
            print(f"{a:#x}")
            print("=" * 60)
            for ins in md.disasm(code, a):
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                if ins.mnemonic == "ret":
                    break
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
