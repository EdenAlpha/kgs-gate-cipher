#!/usr/bin/env python3
"""Runtime map of the game's request classes.

The vtables live in relocated tables that are all-zero in the file, so they can
only be found once the image is loaded.  We scan the mapped data for pointers to
the functions we know, and dump the sub-request vtable we already know.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

SUBREQ_VT = 0x98225A0

FUNCS = {
    "req.set_status": 0x7B2E314,
    "req.set_type": 0x7B2E324,
    "req.set_url_body": 0x7B2E334,
    "req.get_thing": 0x7B2E524,
    "sender.GET": 0x7D03B68,
    "sender.POST": 0x7D03C68,
    "hdr/body builder": 0x7D03E10,
    "sender.POST+hdr": 0x7D04148,
    "cleanup": 0x7D042F0,
    "pump": 0x7D04350,
    "init": 0x7D04444,
    "url.composer": 0x7B099D0,
}


def scan(core, value: int, lo: int, hi: int):
    """Every 8-aligned offset in [lo, hi) holding this 64-bit value."""
    pat = struct.pack("<Q", value)
    hits = []
    step = 4 << 20
    pos = lo
    while pos < hi:
        n = min(step + 8, hi - pos)
        try:
            buf = bytes(core.uc.mem_read(pos, n))
        except Exception:
            pos += step
            continue
        i = buf.find(pat)
        while i >= 0:
            if i % 8 == 0:
                hits.append(pos + i)
            i = buf.find(pat, i + 1)
        pos += step
    return hits


def main() -> int:
    print("[vt] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base
    print(f"[vt] base={B:#x}", flush=True)

    print("\n=== sub-request vtable 0x98225A0 ===", flush=True)
    vt = B + SUBREQ_VT
    byaddr = {a: n for n, a in FUNCS.items()}
    for i in range(0, 20):
        try:
            p = struct.unpack("<Q", bytes(core.uc.mem_read(vt + 8 * i, 8)))[0]
        except Exception:
            break
        if p == 0:
            break
        off = p - B
        print(f"  [{i:2d}] {p:#018x}  {byaddr.get(off, '')}", flush=True)

    print("\n=== who else points at these functions ===", flush=True)
    # the image is one huge sparse RWX mapping; only the data/rodata tail holds
    # vtables, so scan that range rather than the whole mapping
    lo, hi = B + 0x9000000, B + 0xD000000
    for name, va in FUNCS.items():
        for h in scan(core, B + va, lo, hi):
            print(f"  {name:20s} va={va:#x}  table slot at {h:#x} "
                  f"(file va {h - B:#x}, slot {(h - B) // 8})", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
