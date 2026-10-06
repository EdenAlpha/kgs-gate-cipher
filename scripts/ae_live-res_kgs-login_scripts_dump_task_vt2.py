#!/usr/bin/env python3
"""Dump the RUNTIME vtable at 0x98286e8 (the task object state 2 creates)
and 0x98287f0 (the one holding bootstrap_SM), plus the task object layout.
"""
from __future__ import annotations

import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

FDE = os.path.join(HERE, "funcs_eh.txt")


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


def show(fde, core, vt_vaddr, n=16):
    print("=" * 74)
    print(f"RUNTIME VTABLE {vt_vaddr:#x}")
    print("=" * 74)
    try:
        data = bytes(core.uc.mem_read(core.base + vt_vaddr, n * 8))
    except Exception as e:
        print(f"  unreadable: {type(e).__name__}")
        return
    for i in range(n):
        v = struct.unpack_from("<Q", data, i * 8)[0]
        if v == 0:
            print(f"  [{i:2d}] +{i*8:#05x}  (null)")
            continue
        e = enclosing(fde, v)
        if e and v == e[0]:
            tag = f"FN {v:#x} size {e[1]-e[0]:#x}"
        elif e:
            tag = f"fn {e[0]:#x}+{v-e[0]:#x}"
        else:
            tag = f"{v:#x}"
        mark = ""
        if i == 7:
            mark = "   <== state10 calls this"
        elif i == 5:
            mark = "   <== state10 calls this 2nd"
        elif i == 10:
            mark = "   <== bootstrap_SM"
        print(f"  [{i:2d}] +{i*8:#05x}  {v:#018x}  {tag}{mark}")


def main():
    print("[tv] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[tv] ready\n", flush=True)

    fde = load_fde()
    show(fde, core, 0x98286E8)
    print()
    show(fde, core, 0x98287F0)

    # what does the state-2 task object look like?  dump the vtable's
    # neighbours to see the family
    print("\n" + "=" * 74)
    print("neighbouring vtables (0x9828600..0x9828800, first entry only)")
    print("=" * 74)
    for a in range(0x9828600, 0x9828800, 8):
        try:
            v = struct.unpack("<Q", bytes(core.uc.mem_read(core.base + a, 8)))[0]
        except Exception:
            continue
        if v == 0:
            continue
        e = enclosing(fde, v)
        tag = f"FN {v:#x}" if e and v == e[0] else f"{v:#x}"
        print(f"  {a:#x}: {v:#018x}  {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
