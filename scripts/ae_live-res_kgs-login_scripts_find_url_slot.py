"""Find every load/store to object offset 0x3968 (the URL slot) and print the
two HTTP functions in full."""
import os
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48

OFF = 0x3968
IMM12 = OFF // 8          # 0x72d, X-register scaled offset

STR_X_BASE = 0xF9000000   # STR Xt, [Xn, #imm]
LDR_X_BASE = 0xF9400000   # LDR Xt, [Xn, #imm]


def cstr(raw, addr, n=140):
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
    blob = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    words = np.frombuffer(blob, dtype="<u4")

    imm_field = (words >> 10) & 0xFFF
    kind = (words & 0xFFC00000)

    hits = np.nonzero((imm_field == IMM12) &
                      ((kind == STR_X_BASE) | (kind == LDR_X_BASE)))[0]
    print(f"=== {len(hits)} accesses to [xN, #{OFF:#x}] ===")
    for i in hits[:40]:
        addr = int(TEXT_VADDR + i * 4)
        off = addr - TEXT_VADDR + TEXT_OFF
        seq = list(md.disasm(raw[off - 16:off + 12], addr - 16))
        for x in seq:
            mark = "   <== " if x.address == addr else ""
            line = f"  0x{x.address:x}: {x.mnemonic:8} {x.op_str}{mark}"
            if x.mnemonic == "add" and ", #" in x.op_str:
                try:
                    va = int(x.op_str.split("#")[-1].split(",")[0], 16)
                    s = cstr(raw, va)
                    if s:
                        line += f'   ; "{s}"'
                except Exception:
                    pass
            if mark:
                print(line)
        print("  ---")

    for fn, n in ((0x7D017DC, 30), (0x7CDD654, 40)):
        print(f"\n=== fn {fn:#x} (full) ===")
        off = fn - TEXT_VADDR + TEXT_OFF
        adrp = {}
        for ins in md.disasm(raw[off:off + n * 4], fn):
            line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}"
            if ins.mnemonic == "adrp":
                adrp[ins.op_str.split(",")[0].strip()] = \
                    int(ins.op_str.split("#")[-1], 16)
            elif ins.mnemonic == "add" and ", #" in ins.op_str:
                parts = [p.strip() for p in ins.op_str.split(",")]
                try:
                    va = adrp.get(parts[1]) and adrp[parts[1]] + \
                        int(parts[-1].lstrip("#"), 16)
                except Exception:
                    va = None
                if va:
                    s = cstr(raw, va)
                    if s:
                        line += f'        ; "{s}" @{va:#x}'
            if ins.mnemonic == "bl" and "#0x7d038c8" in ins.op_str:
                line += "   ; <== HTTP_POST"
            print(line)
            if ins.mnemonic == "ret":
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
