#!/usr/bin/env python3
"""0x7d017dc directly calls http_post_routine (0x7d038c8) which calls curl.
This is the transport entry point -- see what it expects."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

for a in (0x7D017DC, 0x7D0BDA8):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        f.seek(a - 0x4000)
        code = f.read(0x200)
    print("=" * 74)
    print(f"{a:#x}")
    print("=" * 74)
    n = 0
    for ins in md.disasm(code, a):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
        n += 1
        if ins.mnemonic == "ret" or n > 45:
            break
    print()
