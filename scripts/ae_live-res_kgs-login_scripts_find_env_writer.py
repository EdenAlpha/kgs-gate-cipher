"""Find the code that WRITES the env table (0xa4cff68) and the code that
builds the pes22-game.cs.konami.net URL literal."""
import os
import re
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48

ENV_TABLE = 0xA4CFF68


def cstr(raw, addr, n=140):
    if 0 <= addr < len(raw):
        b = raw[addr:addr + n]
        i = b.find(b"\0")
        if 0 < i < n:
            s = b[:i]
            if all(32 <= c < 127 for c in s) and len(s) >= 3:
                return s.decode("ascii")
    return None


def adrp_refs(raw, page, want_imm=None, window=10):
    """Yield (addr, insn_list) for ADRP loading `page` (+ matching ADD imm)."""
    blob = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    words = np.frombuffer(blob, dtype="<u4")
    is_adrp = (words & 0x9F000000) == 0x90000000
    idx = np.nonzero(is_adrp)[0]
    w = words[idx].astype(np.int64)
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    imm = np.where(imm & 0x100000, imm - 0x200000, imm)
    pc = (TEXT_VADDR + idx.astype(np.int64) * 4) & ~0xFFF
    pages = pc + (imm << 12)
    hit = np.nonzero(pages == page)[0]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    out = []
    for i in hit:
        addr = int(TEXT_VADDR + idx[i] * 4)
        off = addr - TEXT_VADDR + TEXT_OFF
        seq = list(md.disasm(raw[off:off + window * 4], addr))
        if want_imm is not None:
            joined = " | ".join(f"{x.mnemonic} {x.op_str}" for x in seq)
            if f"#{want_imm:#x}" not in joined and f"#{want_imm}" not in joined:
                continue
        out.append((addr, seq))
    return out


def main():
    with open(SO, "rb") as f:
        raw = f.read()

    # locate literals
    print("=== literal occurrences ===")
    for lit in (b"pes22-game.cs.konami.net", b".txt",
                b"CmdGetServerEnv.php", b"gate.php"):
        hits = [m.start() for m in re.finditer(re.escape(lit), raw)]
        print(f"  {lit!r}: {len(hits)} -> {[hex(h) for h in hits[:8]]}")

    print(f"\n=== code referencing env table {ENV_TABLE:#x} ===")
    for addr, seq in adrp_refs(raw, ENV_TABLE & ~0xFFF,
                               want_imm=ENV_TABLE & 0xFFF, window=8):
        print(f"  @ {addr:#x}")
        for x in seq:
            print(f"      0x{x.address:x}: {x.mnemonic:8} {x.op_str}")

    # who reads/writes the host literal
    host_off = raw.find(b"pes22-game.cs.konami.net")
    if host_off > 0:
        print(f"\n=== code referencing host literal @ {host_off:#x} ===")
        for addr, seq in adrp_refs(raw, host_off & ~0xFFF,
                                   want_imm=host_off & 0xFFF, window=6)[:10]:
            print(f"  @ {addr:#x}")
            for x in seq:
                print(f"      0x{x.address:x}: {x.mnemonic:8} {x.op_str}")

    txt_offs = [m.start() for m in re.finditer(re.escape(b".txt"), raw)]
    print(f"\n=== '.txt' literals: {[hex(t) for t in txt_offs[:12]]} ===")
    for t in txt_offs[:6]:
        ctx = cstr(raw, t - 60, 60)
        after = cstr(raw, t, 40)
        print(f"  {t:#x}: before={ctx!r} at={after!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
