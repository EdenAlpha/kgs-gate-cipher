"""Climb the call graph from the game's HTTP POST routine (0x7d038c8) to find
a drivable entry point, and read its prologue to learn the argument layout."""
import os
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48

HTTP_POST = 0x7D038C8
GATEINFO_SENTER = 0x7D0C06C
BOOTSTRAP_SM = 0x7DC7164
WRAPPER = 0x50D6428


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


def disasm(raw, addr, n=64, md=None):
    md = md or Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    off = addr - TEXT_VADDR + TEXT_OFF
    out = []
    for ins in md.disasm(raw[off:off + n * 4], addr):
        out.append(f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}")
        if ins.mnemonic == "ret" and len(out) > 6:
            break
    return out


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    callers, targets = bl_scan(raw)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def callers_of(fn):
        return sorted(set(int(x) for x in callers[targets == fn]))

    print("=== prologue of HTTP POST 0x7d038c8 (arg layout) ===")
    for l in disasm(raw, HTTP_POST, 40, md):
        print(l)

    for start, label in ((HTTP_POST, "HTTP POST 0x7d038c8"),
                         (WRAPPER, "curl wrapper 0x50d6428")):
        print(f"\n=== call graph climbing from {label} ===")
        frontier = [start]
        seen = set()
        for depth in range(1, 7):
            nxt = []
            for fn in frontier:
                for c in callers_of(fn):
                    if c in seen:
                        continue
                    seen.add(c)
                    nxt.append(c)
            if not nxt:
                print(f"  depth {depth}: (no more callers)")
                break
            print(f"  depth {depth}: {len(nxt)} callers -> "
                  f"{[hex(x) for x in nxt[:14]]}")
            frontier = nxt[:14]

    for a, label in ((GATEINFO_SENTER, "GateInfo sender 0x7d0c06c"),
                     (BOOTSTRAP_SM, "bootstrap SM 0x7dc7164")):
        print(f"\n=== {label} prologue ===")
        for l in disasm(raw, a, 30, md):
            print(l)
    return 0


if __name__ == "__main__":
    sys.exit(main())
