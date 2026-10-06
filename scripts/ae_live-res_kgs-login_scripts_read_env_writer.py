"""Disassemble the 4-entry env-table writer (0x73d8488) with string literals
resolved, to learn what keys populate the table and where the data comes from."""
import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF = 0x28293C0, 0x28253C0

TARGETS = [0x7D659C4, 0x7DB6028]
N = 300


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

    for fn in TARGETS:
        print(f"\n{'='*72}\n=== fn {fn:#x} (first {N} insns, strings resolved) ===")
        off = fn - TEXT_VADDR + TEXT_OFF
        adrp = {}
        count = 0
        for ins in md.disasm(raw[off:off + N * 4], fn):
            line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}"
            if ins.mnemonic == "adrp":
                adrp[ins.op_str.split(",")[0].strip()] = \
                    int(ins.op_str.split("#")[-1], 16)
            elif ins.mnemonic in ("add",) and ", #" in ins.op_str:
                parts = [p.strip() for p in ins.op_str.split(",")]
                rd, rs = parts[0], parts[1] if len(parts) > 1 else ""
                try:
                    imm = int(parts[-1].lstrip("#"), 16)
                except Exception:
                    imm = None
                if imm is not None and rs in adrp:
                    va = adrp[rs] + imm
                    s = cstr(raw, va)
                    if s:
                        line += f"        ; \"{s}\" @{va:#x}"
            print(line)
            count += 1
            if ins.mnemonic == "ret" and count > 30:
                break
            if count >= N:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
