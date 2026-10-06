#!/usr/bin/env python3
"""Disassemble the three sub-request methods that call curl_easy_setopt,
to see which one actually performs the HTTP send."""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

FNS = [0x7D03B68, 0x7D03C68, 0x7D04148]


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for a in FNS:
            size = {0x7D03B68: 0x100, 0x7D03C68: 0x158,
                    0x7D04148: 0x194}[a]
            f.seek(a - 0x4000)
            code = f.read(size)
            print("=" * 74)
            print(f"{a:#x}  (size {size:#x})")
            print("=" * 74)
            n = 0
            for ins in md.disasm(code, a):
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                n += 1
                if ins.mnemonic == "ret" or n > 60:
                    break
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
