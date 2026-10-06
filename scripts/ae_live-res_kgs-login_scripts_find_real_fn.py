"""Find the REAL enclosing function of each bl-to-HTTP_POST site by walking
back to the prologue, then find callers of that function."""
import os
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48

# `sub sp, sp, #imm12`  ->  1101 0001 00 imm12 Rn=11111 Rd=11111
SUB_SP = 0xD10003FF
SUB_SP_MASK = 0xFFC003FF
# `stp x29, x30, [sp, #imm]` (signed offset) -> 1010 1001 00 imm7 11111 11111 11010
STP_FP = 0xA9007BFD
STP_FP_MASK = 0xFFC003FF


def bl_scan(raw):
    blob = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    words = np.frombuffer(blob, dtype="<u4")
    is_bl = (words & 0xFC000000) == 0x94000000
    idx = np.nonzero(is_bl)[0]
    imm = (words[idx] & 0x03FFFFFF).astype(np.int64)
    imm = np.where(imm & 0x2000000, imm - 0x4000000, imm)
    callers = (TEXT_VADDR + idx.astype(np.int64) * 4)
    targets = callers + imm * 4
    return callers, targets


def function_starts(raw):
    """Candidate function entries = instruction after each `ret`, plus BL
    targets. `ret` (0xd65f03c0) reliably delimits straight-line code."""
    blob = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    words = np.frombuffer(blob, dtype="<u4")
    starts = set()

    is_ret = words == 0xD65F03C0
    for i in np.nonzero(is_ret)[0]:
        starts.add(int(TEXT_VADDR + i * 4) + 4)

    is_bl = (words & 0xFC000000) == 0x94000000
    idx = np.nonzero(is_bl)[0]
    imm = (words[idx] & 0x03FFFFFF).astype(np.int64)
    imm = np.where(imm & 0x2000000, imm - 0x4000000, imm)
    tg = (TEXT_VADDR + idx.astype(np.int64) * 4) + imm * 4
    for t in np.unique(tg):
        starts.add(int(t))
    return np.array(sorted(starts), dtype=np.int64), words, idx, imm


def enclosing(starts, addr):
    i = np.searchsorted(starts, addr, side="right") - 1
    return int(starts[i]) if i >= 0 else None


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    callers, targets = bl_scan(raw)
    starts, words, idx, imm = function_starts(raw)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def callers_of(fn):
        return sorted(set(int(x) for x in callers[targets == fn]))

    for site in (0x7D01830, 0x7D159F0):
        fn = enclosing(starts, site)
        print(f"\n=== bl-site {site:#x} -> enclosing {fn} "
              f"({fn and hex(fn)}) span {site - fn:#x} ===")
        if fn:
            off = fn - TEXT_VADDR + TEXT_OFF
            for ins in list(md.disasm(raw[off:off + 16 * 4], fn))[:14]:
                print(f"      0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}")
            cs = callers_of(fn)
            print(f"      direct bl callers: {len(cs)} "
                  f"{[hex(x) for x in cs[:12]]}")
            for c in cs[:6]:
                g = enclosing(starts, c)
                gs = callers_of(g) if g else []
                print(f"        {c:#x} in fn {g and hex(g)} -> callers "
                      f"{[hex(x) for x in gs[:8]]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
