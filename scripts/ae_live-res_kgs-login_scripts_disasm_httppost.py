#!/usr/bin/env python3
"""Disassemble http_post_routine 0x7d038c8 fully to see exactly what the
request object must contain for it to reach curl."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
with open(SO, "rb") as f:
    f.seek(0x7D038C8 - 0x4000)
    code = f.read(0x160)

print("http_post_routine 0x7d038c8 (size 0x160)")
print("=" * 74)
for ins in md.disasm(code, 0x7D038C8):
    print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
