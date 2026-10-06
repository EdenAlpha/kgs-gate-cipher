#!/usr/bin/env python3
"""0x7dc91d8 takes the command-name string and returns a task object.
Disassemble it plus the string global's layout."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

FNS = [0x7DC91D8, 0x7DC8C80]


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for a in FNS:
            f.seek(a - 0x4000)
            code = f.read(0x200)
            print("=" * 74)
            print(f"{a:#x}")
            print("=" * 74)
            n = 0
            for ins in md.disasm(code, a):
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                n += 1
                if ins.mnemonic == "ret" or n > 55:
                    break
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
