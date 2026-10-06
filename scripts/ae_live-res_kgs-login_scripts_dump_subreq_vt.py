#!/usr/bin/env python3
"""Dump the sub-request vtable 0x98225a0 (what http_post_routine builds and
what actually sends), and disassemble its methods."""
from __future__ import annotations

import os
import struct
import sys
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
FDE = os.path.join(HERE, "funcs_eh.txt")

SUBREQ_VT = 0x98225A0


def load_fde():
    out = []
    with open(FDE, encoding="utf-8") as f:
        for line in f:
            p = line.split()
            out.append((int(p[0], 16), int(p[1], 16)))
    return out


def enclosing(fde, addr):
    lo, hi = 0, len(fde) - 1
    best = None
    while lo <= hi:
        m = (lo + hi) // 2
        if fde[m][0] <= addr:
            best = m
            lo = m + 1
        else:
            hi = m - 1
    if best is None:
        return None
    a, b = fde[best]
    return (a, b) if a <= addr < b else None


def main():
    from peerlink.online_client import OnlineCore, REGISTRARS
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    sys.path.insert(0, HERE)

    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base
    fde = load_fde()

    print("=" * 74)
    print(f"SUB-REQUEST VTABLE {SUBREQ_VT:#x} (runtime)")
    print("=" * 74)
    try:
        vtd = bytes(core.uc.mem_read(B + SUBREQ_VT, 16 * 8))
    except Exception as e:
        print(f"  unreadable: {type(e).__name__}")
        return 1
    fns = {}
    for i in range(16):
        v = struct.unpack_from("<Q", vtd, i * 8)[0]
        if v == 0:
            continue
        e = enclosing(fde, v - B) if B <= v < B + 0x100000000 else None
        if e and v - B == e[0]:
            tag = f"FN {v - B:#x} size {e[1]-e[0]:#x}"
            fns[i] = v - B
        elif e:
            tag = f"fn {e[0]:#x}+{v - B - e[0]:#x}"
        else:
            tag = f"{v:#x}"
        print(f"  [{i:2d}] +{i*8:#05x}  {v:#018x}  {tag}")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    print("\n" + "=" * 74)
    print("sub-request vtable methods")
    print("=" * 74)
    with open(SO, "rb") as f:
        for i, a in sorted(fns.items()):
            f.seek(a - 0x4000)
            code = f.read(0x80)
            print(f"\n  [{i}] {a:#x}:")
            n = 0
            for ins in md.disasm(code, a):
                print(f"      {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                n += 1
                if n > 14:
                    break
    return 0


if __name__ == "__main__":
    sys.exit(main())
