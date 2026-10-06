"""Static caller scan: find every `bl` in .text targeting a given vaddr.

Two targets:
  curl_easy_setopt (0x6886498)  -> which game functions set a URL/body
  the URL concat chain           -> where the base string is composed

Also: find code referencing the CmdGetServerEnv.php literal, i.e. the
'server environment' fetch.
"""
import os
import struct
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

CURLOPT_SETOPT = 0x6886498
CONCAT_CHAIN = 0x7DBC7F8
SERVERENV_STR = 0xA0026E          # "CmdGetServerEnv.php" (rodata, vaddr==offset)
GATE_STR = 0x9D9A1B               # "gate.php"


def bl_callers(raw, target):
    """Return [caller_vaddr] for every A64 BL reaching `target`."""
    blob = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    words = np.frombuffer(blob, dtype="<u4")
    is_bl = (words & 0xFC000000) == 0x94000000
    idx = np.nonzero(is_bl)[0]
    imm = (words[idx] & 0x03FFFFFF).astype(np.int64)
    imm = np.where(imm & 0x2000000, imm - 0x4000000, imm)
    targets = (TEXT_VADDR + idx.astype(np.int64) * 4) + imm * 4
    hit = np.nonzero(targets == target)[0]
    return [int(TEXT_VADDR + idx[i] * 4) for i in hit]


def blr_callers(raw, target):
    """Return caller addresses for BR/BLR-free indirect references (unused)."""
    return []


def adrp_refs(raw, page_vaddr):
    """Find ADRP instructions loading `page_vaddr`, plus following insns."""
    blob = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    words = np.frombuffer(blob, dtype="<u4")
    is_adrp = (words & 0x9F000000) == 0x90000000
    idx = np.nonzero(is_adrp)[0]
    if idx.size == 0:
        return []
    w = words[idx].astype(np.int64)
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    imm = np.where(imm & 0x100000, imm - 0x200000, imm)   # sign-extend 21 bits
    pc = TEXT_VADDR + idx.astype(np.int64) * 4
    pc &= ~0xFFF
    pages = pc + (imm << 12)
    hit = np.nonzero(pages == page_vaddr)[0]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    out = []
    for i in hit[:60]:
        addr = int(TEXT_VADDR + idx[i] * 4)
        blob2 = raw[addr - TEXT_VADDR + TEXT_OFF:
                    addr - TEXT_VADDR + TEXT_OFF + 16]
        seq = [f"{x.mnemonic} {x.op_str}" for x in md.disasm(blob2, addr)]
        out.append((addr, seq))
    return out


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    print(f"loaded {len(raw):,} bytes\n")

    for name, tgt in (("curl_easy_setopt", CURLOPT_SETOPT),
                      ("URL concat chain", CONCAT_CHAIN)):
        hits = bl_callers(raw, tgt)
        print(f"=== direct bl callers of {name} ({tgt:#x}): {len(hits)} ===")
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        for a in hits[:40]:
            off = a - TEXT_VADDR + TEXT_OFF
            # walk back a little to show context
            ctx = []
            for ins in md.disasm(raw[off - 24:off + 8], a - 24):
                ctx.append(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
            print(f"  at {a:#x}:")
            for c in ctx[-8:]:
                print(f"      {c}")
        print()

    for name, pg, s in (("CmdGetServerEnv.php", SERVERENV_STR & ~0xFFF,
                         SERVERENV_STR & 0xFFF),
                        ("gate.php", GATE_STR & ~0xFFF, GATE_STR & 0xFFF)):
        refs = adrp_refs(raw, pg)
        print(f"=== ADRP loading page {pg:#x} (for {name} at +{s:#x}): "
              f"{len(refs)} hits ===")
        for addr, seq in refs:
            joined = " | ".join(seq)
            if f"#{s:#x}" in joined or f"#{s}" in joined:
                print(f"  HIT {addr:#x}: {joined}")
        for addr, seq in refs[:12]:
            print(f"  {addr:#x}: {' | '.join(seq)}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
