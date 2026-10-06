#!/usr/bin/env python3
"""Disassemble 0x8132360 (writes 5 table entries) to see if its store to
0xa4cf018 is static or via a dynamic register."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
with open(SO, "rb") as f:
    f.seek(0x8132360 - 0x4000)
    code = f.read(0x200)

print("0x8132360")
print("=" * 74)
for ins in md.disasm(code, 0x8132360):
    mark = ""
    if ins.address == 0x81324F4:
        mark = "  <== store to 0xa4cf018"
    print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}{mark}")
