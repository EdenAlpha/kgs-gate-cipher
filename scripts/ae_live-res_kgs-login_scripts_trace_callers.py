"""Trace how the callers of HTTP POST (0x7d038c8) build x1 = the URL."""
import os
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48

CALLERS = [0x7D01830, 0x7D159F0]
TARGET = 0x7D038C8


def cstr(raw, addr, n=120):
    if 0 <= addr < len(raw):
        b = raw[addr:addr + n]
        i = b.find(b"\0")
        if 0 < i < n:
            s = b[:i]
            if all(32 <= c < 127 for c in s) and len(s) >= 3:
                return s.decode("ascii")
    return None


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    for fn in CALLERS:
        off = fn - TEXT_VADDR + TEXT_OFF
        print(f"\n{'='*70}\n=== caller {fn:#x} — first 90 insns ===")
        adrp = {}
        insns = list(md.disasm(raw[off:off + 90 * 4], fn))
        for ins in insns:
            line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}"
            if ins.mnemonic == "adrp":
                adrp[ins.op_str.split(",")[0].strip()] = \
                    int(ins.op_str.split("#")[-1], 16)
            elif ins.mnemonic in ("add", "ldr") and "#0x" in ins.op_str:
                parts = [p.strip() for p in ins.op_str.split(",")]
                rd = parts[0]
                try:
                    imm = int(parts[-1].split("#")[-1], 16)
                except Exception:
                    imm = None
                if imm is not None and rd in adrp:
                    va = adrp[rd] + imm
                    s = cstr(raw, va)
                    if s:
                        line += f"        ; str@{va:#x} = {s!r}"
            if ins.mnemonic == "bl":
                if "#0x7d038c8" in ins.op_str:
                    line += "        ; <== CALL HTTP_POST (URL = x1)"
                elif "#0x6886498" in ins.op_str:
                    line += "        ; curl_easy_setopt"
                elif "#0x6858c98" in ins.op_str:
                    line += "        ; curl_easy_init"
            print(line)
            if ins.mnemonic == "ret" and len(insns) > 10:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
