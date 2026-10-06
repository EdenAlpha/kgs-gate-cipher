"""Resolve the '.txt' literal reference and the env-table writer."""
import os
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48

TXT = 0xA5ED6F
HOST = 0xA5ED56
ENV = 0xA4CFF68


def cstr(raw, addr, n=160):
    if 0 <= addr < len(raw):
        b = raw[addr:addr + n]
        i = b.find(b"\0")
        if 0 < i < n:
            s = b[:i]
            if all(32 <= c < 127 for c in s) and len(s) >= 3:
                return s.decode("ascii")
    return None


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


def adrp_refs(raw, page, want_imm=None, window=14):
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
            if f"#{want_imm:#x}" not in joined:
                continue
        out.append((addr, seq))
    return out


def containing(raw, targets, addr):
    uniq = np.unique(targets)
    i = np.searchsorted(uniq, addr, side="right") - 1
    return int(uniq[i]) if i >= 0 else None


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    callers, targets = bl_scan(raw)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def callers_of(fn):
        return sorted(set(int(x) for x in callers[targets == fn]))

    print(f"=== literal bytes at {TXT - 26:#x} ===")
    seg = raw[TXT - 26:TXT + 24]
    print(f"  {' '.join(f'{b:02x}' for b in seg)}")
    print(f"  ascii: {''.join(chr(b) if 32 <= b < 127 else '.' for b in seg)}")

    print(f"\n=== code referencing '.txt' @ {TXT:#x} ===")
    refs = adrp_refs(raw, TXT & ~0xFFF, want_imm=TXT & 0xFFF, window=16)
    if not refs:
        print("  (no ADRP+ADD reference — searched for exact imm)")
    for addr, seq in refs[:8]:
        print(f"\n  @ {addr:#x}")
        for x in seq:
            print(f"      0x{x.address:x}: {x.mnemonic:8} {x.op_str}")
        fn = containing(raw, targets, addr)
        cs = callers_of(fn)
        print(f"      enclosing fn {fn:#x} callers={[hex(c) for c in cs[:10]]}")

    print(f"\n=== code referencing host literal @ {HOST:#x} ===")
    for addr, seq in adrp_refs(raw, HOST & ~0xFFF, want_imm=HOST & 0xFFF,
                               window=20)[:4]:
        print(f"  @ {addr:#x}")
        for x in seq:
            print(f"      0x{x.address:x}: {x.mnemonic:8} {x.op_str}")

    # env table: enclosing fn of the writer and its callers
    print(f"\n=== env-table writer 0x8149744 chain ===")
    fn = containing(raw, targets, 0x8149744)
    print(f"  enclosing fn {fn:#x}")
    cs = callers_of(fn)
    print(f"  callers {[hex(c) for c in cs[:12]]}")
    for c in cs[:5]:
        g = containing(raw, targets, c)
        print(f"    {c:#x} in fn {g:#x} -> its callers "
              f"{[hex(x) for x in callers_of(g)][:8]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
