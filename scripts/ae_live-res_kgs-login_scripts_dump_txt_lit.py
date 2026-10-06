#!/usr/bin/env python3
"""Dump the string region around the game-host literal (0xa5ed56) and the
'.txt' literal (0xa5ed6f), then find every code site that references them.

If the game fetches a config document from the CS host, this is where the
URL shape lives.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

HOST_LIT = 0xa5ed56
TXT_LIT = 0xa5ed6f

REF_LO, REF_HI = 0x28293c0, 0x28293c0 + 0x6000000   # .text vaddr window


def main():
    with open(SO, "rb") as f:
        # strings: offset == vaddr
        f.seek(0xa5e000)
        blob = f.read(0x2000)

    print("=" * 72)
    print("STRING REGION around 0xa5ed56 (host) / 0xa5ed6f (.txt)")
    print("=" * 72)
    base = 0xa5e000
    # print every NUL-terminated printable string in the window
    i = 0
    while i < len(blob):
        if 32 <= blob[i] < 127:
            j = i
            while j < len(blob) and 32 <= blob[j] < 127:
                j += 1
            if j < len(blob) and blob[j] == 0 and j - i >= 3:
                s = blob[i:j].decode("ascii")
                addr = base + i
                mark = ""
                if addr == HOST_LIT:
                    mark = "   <== HOST_LIT"
                elif addr == TXT_LIT:
                    mark = "   <== TXT_LIT"
                print(f"  {addr:#09x}: {s!r}{mark}")
                i = j + 1
                continue
        i += 1

    # exact bytes at the two known literals
    for label, a in (("HOST_LIT", HOST_LIT), ("TXT_LIT", TXT_LIT)):
        off = a - base
        raw = blob[off:off + 48]
        end = raw.find(b"\0")
        print(f"\n  {label} {a:#x} -> {raw[:end if end >= 0 else 48]!r}")

    # ------------------------------------------------------------ xref scan
    print("\n" + "=" * 72)
    print("CODE REFERENCES (ADR/ADRP+ADD -> these literals)")
    print("=" * 72)

    with open(SO, "rb") as f:
        f.seek(0x28253c0)                 # .text file offset
        text = f.read(0x6000000)

    text_vaddr = 0x28293c0

    def page(v):
        return v & ~0xFFF

    def pgoff(v):
        return v & 0xFFF

    def imm_hi(insn):
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        v = (immhi << 2) | immlo
        if v & (1 << 20):
            v -= 1 << 21
        return v << 12

    def imm12(insn):
        v = (insn >> 10) & 0xFFF
        if v & (1 << 11):
            v -= 1 << 12
        return v

    hits = {HOST_LIT: [], TXT_LIT: []}

    # single forward pass: remember only the immediately-preceding ADRP
    # (ADD almost always follows it) to keep memory flat.
    last_adrp = (None, None)          # (rd, page)
    n = len(text) // 4
    for idx in range(n):
        insn = struct.unpack_from("<I", text, idx * 4)[0]
        if (insn & 0x9F000000) == 0x90000000:          # ADRP
            rd = insn & 0x1F
            pc = text_vaddr + idx * 4
            last_adrp = (rd, (pc & ~0xFFF) + imm_hi(insn))
            continue
        if (insn & 0x9F000000) == 0x10000000:          # ADR (exact addr)
            rd = insn & 0x1F
            pc = text_vaddr + idx * 4
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            v = (immhi << 2) | immlo
            if v & (1 << 20):
                v -= 1 << 21
            tgt = pc + v
            if tgt in hits:
                hits[tgt].append(pc)
            continue
        if (insn & 0xFFC00000) == 0x91000000:          # ADD imm
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            if last_adrp[0] == rn:
                tgt = last_adrp[1] + imm12(insn)
                if tgt in hits:
                    hits[tgt].append(text_vaddr + idx * 4)

    for lit, sites in hits.items():
        name = "HOST_LIT" if lit == HOST_LIT else "TXT_LIT"
        print(f"\n  {name} {lit:#x}: {len(sites)} reference(s)")
        for s in sites[:40]:
            print(f"      from {s:#x}")

    # also: any literal in this region that is a .txt / config-ish path
    print("\n" + "=" * 72)
    print("ALL '.txt'-style literals in 0xa5e000..0xa60000")
    print("=" * 72)
    i = 0
    while i < len(blob):
        if 32 <= blob[i] < 127:
            j = i
            while j < len(blob) and 32 <= blob[j] < 127:
                j += 1
            if j < len(blob) and blob[j] == 0:
                s = blob[i:j].decode("ascii")
                if ".txt" in s or ".json" in s or ".yml" in s \
                        or "http" in s or s.endswith(".php"):
                    print(f"  {base + i:#09x}: {s!r}")
                i = j + 1
                continue
        i += 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
