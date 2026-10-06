#!/usr/bin/env python3
"""Disassemble the session methods (first ~18 instructions each) to see
what they do and what they call."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

M = [
    (0x7CDB974, "m4"), (0x7CDB9D0, "m5"), (0x7CE1A48, "m6"),
    (0x7CE1ACC, "m7"), (0x7CDBA60, "m8"), (0x7CDC3D8, "m9"),
    (0x7CDC414, "m10"), (0x7CDC6E8, "m11"), (0x7CDCA20, "m12"),
    (0x7CDCAD4, "m13"), (0x7CDCAB4, "m14"), (0x7CE1860, "m15"),
    (0x7CE1974, "m16"), (0x7CE1480, "m17"), (0x7CE157C, "m18"),
    (0x7CE158C, "m19"), (0x7CE1594, "m20"), (0x7CE159C, "m21"),
    (0x7CE15A4, "m22"), (0x7CE15AC, "m23"), (0x7CDCAF4, "m24"),
    (0x7CE1334, "m25"), (0x7CE1450, "m26"), (0x7CDD7CC, "m27"),
    (0x7CDD70C, "m28"), (0x7CDD790, "m29"), (0x7CDD7AC, "m30"),
    (0x7CDD7B4, "m31"),
]


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for a, name in M:
            f.seek(a - 0x4000)
            code = f.read(0x90)
            print(f"--- {name} {a:#x} ---")
            n = 0
            for ins in md.disasm(code, a):
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                n += 1
                if ins.mnemonic in ("ret", "b") and n > 4:
                    break
                if n > 16:
                    break
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
