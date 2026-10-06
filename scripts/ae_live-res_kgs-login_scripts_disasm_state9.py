#!/usr/bin/env python3
"""State 9 (0x7dc747c..0x7dc7860) is the handler that creates the task at
0x7dc77fc.  See what it needs in ctx to reach that point."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
with open(SO, "rb") as f:
    f.seek(0x7DC747C - 0x4000)
    code = f.read(0x7DC7860 - 0x7DC747C)

print("state 9 handler 0x7dc747c..0x7dc7860")
print("=" * 74)
for ins in md.disasm(code, 0x7DC747C):
    mark = "  <== creates task" if ins.address == 0x7DC77FC else ""
    print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}{mark}")
