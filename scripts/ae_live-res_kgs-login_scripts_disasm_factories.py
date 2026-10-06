#!/usr/bin/env python3
"""Disassemble the task-factory helpers the login SM calls in states 3-9.

The SM's pattern is:
    bl   0x7cda454        -> x0
    cbz  x0, fail         ; NULL = give up
    mov  x20, x0
    bl   0x7cda5cc        ; (obj, 1) -> w0
So we need each helper's return convention to stub it correctly.
"""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

FNS = [
    0x7CDA280, 0x7CDA3B8, 0x7CDA454, 0x7CDA4C0,
    0x7CDA534, 0x7CDA5CC, 0x7CDA78C, 0x7CDA808,
    0x7CDAF90, 0x7B1CF34,
]


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for a in FNS:
            f.seek(a - 0x4000)
            code = f.read(0x120)
            print("=" * 74)
            print(f"{a:#x}")
            print("=" * 74)
            n = 0
            for ins in md.disasm(code, a):
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                n += 1
                if ins.mnemonic == "ret" or n > 40:
                    break
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
