#!/usr/bin/env python3
"""The task-factory helpers all do:

    adrp x8, #0xa4ab000 ; ldr w8, [x8, #0x6a0]   ; mode global
    ... / ldr x0, [x8, #0x6a8]                    ; SESSION object

So *(0xa4ab6a8) is the live session.  If the registrars populated it, its
vtable holds the real task methods -- no fabrication needed.
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
MODE = 0xA4AB6A0
SESS = 0xA4AB6A8


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
    print("[sess] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[sess] ready\n", flush=True)

    B = core.base

    def rd(a, n=8):
        try:
            return bytes(core.uc.mem_read(B + a, n))
        except Exception:
            return b""

    mode = struct.unpack("<I", rd(MODE, 4))[0]
    sess = struct.unpack("<Q", rd(SESS, 8))[0]
    print(f"mode  @ {MODE:#x} = {mode}")
    print(f"sess  @ {SESS:#x} = {sess:#x}")

    if sess == 0:
        print("\n*** session global is NULL -- registrars did not create it ***")
        print("    (the helpers all return 0 / NULL in that case)")
        # show the region so we can see what IS there
        print("\nregion 0xa4ab600..0xa4ab700:")
        raw = rd(0xA4AB600, 0x100)
        for off in range(0, len(raw), 8):
            v = struct.unpack_from("<Q", raw, off)[0]
            if v == 0:
                continue
            tag = f" -> {v - B:#x}" if B <= v < B + 0x100000000 else ""
            print(f"    +{off:#06x}: {v:#018x}{tag}")
        return 0

    print(f"\n*** SESSION OBJECT at {sess:#x} (vaddr {sess - B:#x}) ***")
    fde = load_fde()

    vt = struct.unpack("<Q", bytes(core.uc.mem_read(sess, 8)))[0]
    print(f"session->vtable = {vt:#x} (vaddr {vt - B:#x})")

    print("\nfirst 0x80 bytes of the session object:")
    raw = bytes(core.uc.mem_read(sess, 0x80))
    for off in range(0, len(raw), 8):
        v = struct.unpack_from("<Q", raw, off)[0]
        if v == 0:
            continue
        tag = ""
        e = enclosing(fde, v - B) if B <= v < B + 0x100000000 else None
        if e and v - B == e[0]:
            tag = f"  FN {e[0]:#x}"
        elif e:
            tag = f"  fn {e[0]:#x}+{v - B - e[0]:#x}"
        print(f"    +{off:#06x}: {v:#018x}{tag}")

    print("\nits vtable (first 32 entries):")
    try:
        vtd = bytes(core.uc.mem_read(vt, 32 * 8))
    except Exception as e:
        print(f"    unreadable: {type(e).__name__}")
        return 0
    for i in range(32):
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
        print(f"    [{i:2d}] +{i*8:#05x}  {v:#018x}  {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
