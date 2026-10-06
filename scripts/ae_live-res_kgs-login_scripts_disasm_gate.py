#!/usr/bin/env python3
"""State 9 calls 0x8142ee0(1) and 0x81432d0(obj,0) and bails if either is 0.
See what they check -- that's what's missing."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for a in (0x8142EE0, 0x81432D0):
    with open(SO, "rb") as f:
        f.seek(a - 0x4000)
        code = f.read(0x120)
    print("=" * 74)
    print(f"{a:#x}")
    print("=" * 74)
    n = 0
    for ins in md.disasm(code, a):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
        n += 1
        if ins.mnemonic == "ret" or n > 35:
            break
    print()
