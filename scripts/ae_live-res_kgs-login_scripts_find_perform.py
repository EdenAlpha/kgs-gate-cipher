"""Locate curl_easy_perform: the `bl` immediately after the setopt cluster in
HTTP_POST 0x7d038c8."""
import os
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF = 0x28293C0, 0x28253C0

SETOPT = 0x6886498
INIT = 0x6858C98


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    print("=== tail of HTTP_POST 0x7d03d44 .. 0x7d03e60 ===")
    off = 0x7D03D44 - TEXT_VADDR + TEXT_OFF
    for ins in md.disasm(raw[off:off + 0x120], 0x7D03D44):
        line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}"
        if ins.mnemonic == "bl":
            if f"#{SETOPT:#x}" in ins.op_str:
                line += "   ; curl_easy_setopt"
            elif f"#{INIT:#x}" in ins.op_str:
                line += "   ; curl_easy_init"
            else:
                line += "   ; <== candidate"
        print(line)
        if ins.mnemonic == "ret":
            break

    # find functions calling BOTH setopt and the candidate
    print("\n=== all distinct `bl` targets in 0x7d038c8..0x7d04400 ===")
    start, end = 0x7D038C8, 0x7D04400
    seen = set()
    for ins in md.disasm(raw[start - TEXT_VADDR + TEXT_OFF:
                             end - TEXT_VADDR + TEXT_OFF], start):
        if ins.mnemonic == "bl":
            try:
                t = int(ins.op_str.lstrip("#"), 16)
            except Exception:
                continue
            if t not in (SETOPT, INIT) and t not in seen:
                seen.add(t)
                print(f"  {ins.address:#x} -> {t:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
