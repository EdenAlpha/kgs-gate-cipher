#!/usr/bin/env python3
"""0x8137f9c populates the online command table at 0xa4cf018.
Disassemble it to learn its signature and what it needs."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
with open(SO, "rb") as f:
    f.seek(0x8137F9C - 0x4000)
    code = f.read(0x438)

print("0x8137f9c (size 0x438) -- command table initializer")
print("=" * 74)
for ins in md.disasm(code, 0x8137F9C):
    mark = ""
    if ins.address in (0x8137FF8, 0x81382BC):
        mark = "  <== writes the table"
    print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}{mark}")
