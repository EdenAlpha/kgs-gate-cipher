#!/usr/bin/env python3
"""Search for live objects by their *vtable* pointer (not the fn table).

The command class vtable is the static at 0x97d4448 -> in emulated memory
that is base + 0x97d4448 = 0x100097d4448.  An instance's first qword points
at its vtable, so scanning for that address finds instances.

Also try the sub-vtables (+0x48, +0x78) and the other static vtables.
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

CANDIDATES = {
    "cmdclass_vt      0x97d4448": 0x100097D4448,
    "cmdclass_vt+0x48 0x97d4490": 0x100097D4490,
    "cmdclass_vt+0x78 0x97d44c0": 0x100097D44C0,
    "other_vt         0x97a2600": 0x100097A2600,
    "other_vt+0x48    0x97a2648": 0x100097A2648,
    "other_vt+0x78    0x97a2678": 0x100097A2678,
    "bootstrap_fn_tbl 0x98287f0": 0x100098287F0,
    "http_fn_tbl      0x9822280": 0x10009822280,
    "gateinfo_fn_tbl  0x98228e8": 0x100098228E8,
}


def scan_for(core, target):
    pat = struct.pack("<Q", target)
    out = []
    for start, end, _p in core.uc.mem_regions():
        size = end - start
        if size <= 0 or size > 1 << 32:
            continue
        off = 0
        while off < size:
            n = min(4 << 20, size - off)
            try:
                buf = bytes(core.uc.mem_read(start + off, n))
            except Exception:
                break
            i = buf.find(pat)
            if i >= 0:
                out.append(start + off + i)
            off += n
    return out


def main():
    print("[vt] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[vt] ready\n", flush=True)

    for name, vt in CANDIDATES.items():
        hits = scan_for(core, vt)
        print(f"{name}  {vt:#x}  -> {len(hits)} ptr(s)")
        for h in hits[:4]:
            print(f"      at {h:#x}")
            try:
                raw = bytes(core.uc.mem_read(h - 0x30, 0x90))
            except Exception:
                continue
            for off in range(0, len(raw), 8):
                at = h - 0x30 + off
                v = struct.unpack_from("<Q", raw, off)[0]
                if v == 0:
                    continue
                sel = "     >>" if at == h else "        "
                tag = ""
                if core.base <= v < core.base + 0x100000000:
                    tag = f" -> {v - core.base:#x}"
                print(f"      {sel} {at:#x}: {v:#018x}{tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
