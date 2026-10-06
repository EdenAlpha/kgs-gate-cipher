#!/usr/bin/env python3
"""Disassemble the CmdGetServerEnv task's own vtable methods to find which
one performs the HTTP request."""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

# task vtable 0x9828a90 entries that are the task's OWN methods
METH = {
    3: 0x7DC8FBC, 4: 0x7DC9248, 7: 0x745AAEC,
    8: 0x7DC911C, 9: 0x7DC91C4, 10: 0x7DC91C8, 11: 0x7DC91D0,
    0: 0x745AAE0, 1: 0x66D1CD4, 2: 0x7B1F37C, 5: 0x8144AA8,
    6: 0x66D1D08, 12: 0x745AAF4,
}


def main():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for idx, a in sorted(METH.items()):
            f.seek(a - 0x4000)
            code = f.read(0x140)
            print("=" * 74)
            print(f"vtable[{idx}] = {a:#x}")
            print("=" * 74)
            n = 0
            for ins in md.disasm(code, a):
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                n += 1
                if ins.mnemonic == "ret" or n > 30:
                    break
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
