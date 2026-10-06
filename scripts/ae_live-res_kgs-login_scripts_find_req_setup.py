#!/usr/bin/env python3
"""The transport builds a request (vtable 0x9822580) with +0x28..+0x60
zeroed, but http_post_routine bails unless req->[0x30] is a valid object.
Find (a) the request vtable's methods and (b) who calls the transport.
"""
from __future__ import annotations

import os
import struct
import sys
import time
from collections import defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
FDE = os.path.join(HERE, "funcs_eh.txt")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

TRANSPORT = 0x7D017DC
REQ_VT = 0x9822580


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
    fde = load_fde()

    # ---- who calls the transport? -------------------------------------
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)
    callers = defaultdict(list)
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        if (i & 0xFC000000) == 0x94000000:
            imm = i & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = TEXT_VADDR + idx * 4
            t = pc + (imm << 2)
            if t == TRANSPORT:
                e = enclosing(fde, pc)
                callers[t].append((pc, e[0] if e else None))

    print("=" * 74)
    print(f"CALLERS of transport {TRANSPORT:#x}")
    print("=" * 74)
    for _, sites in callers.items():
        for pc, fn in sites[:10]:
            print(f"  {pc:#x}  in fn {fn:#x}" if fn else f"  {pc:#x}")

    # ---- dump the request vtable at runtime ----------------------------
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

    print("\n" + "=" * 74)
    print(f"REQUEST VTABLE {REQ_VT:#x} (runtime)")
    print("=" * 74)
    try:
        vtd = bytes(core.uc.mem_read(B + REQ_VT, 16 * 8))
    except Exception as e:
        print(f"  unreadable: {type(e).__name__}")
        return 1
    for i in range(16):
        v = struct.unpack_from("<Q", vtd, i * 8)[0]
        if v == 0:
            continue
        e = enclosing(fde, v - B) if B <= v < B + 0x100000000 else None
        if e and v - B == e[0]:
            tag = f"FN {v - B:#x} size {e[1]-e[0]:#x}"
        elif e:
            tag = f"fn {e[0]:#x}+{v - B - e[0]:#x}"
        else:
            tag = f"{v:#x}"
        print(f"  [{i:2d}] +{i*8:#05x}  {v:#018x}  {tag}")

    # ---- disassemble the request vtable's first methods ----------------
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    print("\n" + "=" * 74)
    print("request vtable methods (first 12 instrs each)")
    print("=" * 74)
    with open(SO, "rb") as f:
        for i in range(16):
            v = struct.unpack_from("<Q", vtd, i * 8)[0]
            if v == 0 or not (B <= v < B + 0x100000000):
                continue
            a = v - B
            f.seek(a - 0x4000)
            code = f.read(0x60)
            print(f"\n  [{i}] {a:#x}:")
            n = 0
            for ins in md.disasm(code, a):
                print(f"      {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                n += 1
                if n > 11:
                    break
    return 0


if __name__ == "__main__":
    sys.exit(main())
