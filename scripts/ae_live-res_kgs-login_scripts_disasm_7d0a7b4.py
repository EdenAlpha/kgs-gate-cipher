#!/usr/bin/env python3
"""0x7d0a7b4 is called with the built sub-request; it should reach curl.
See how it reads the URL (subreq->[0x38]) to learn the string layout."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
with open(SO, "rb") as f:
    f.seek(0x7D0A7B4 - 0x4000)
    code = f.read(0x180)

print("0x7d0a7b4")
print("=" * 74)
for ins in md.disasm(code, 0x7D0A7B4):
    print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
