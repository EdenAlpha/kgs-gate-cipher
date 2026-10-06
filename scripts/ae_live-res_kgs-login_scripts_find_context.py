#!/usr/bin/env python3
"""Find the live objects whose vtables are the ones we discovered.

bootstrap_SM 0x7dc7164 is a virtual method; its vtable sits at ~0x100098287f0.
cmdenv_dispatcher 0x767cecc is a virtual method; its vtable ~0x100097d4410.

An object's first qword is its vtable pointer, so scanning memory for those
addresses finds the instances. Report each hit with its neighbourhood so we
can see the object's other fields.
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

VTABLES = {
    "bootstrap_SM_vt":  0x100098287F0,
    "cmdenv_disp_vt":   0x100097D4410,
    "cmdenv_disp_vt2":  0x100097D43B0,
    "http_post_vt":     0x10009822280,
    "gateinfo_vt":      0x100098228E8,
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
    print("[ctx] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[ctx] ready\n", flush=True)

    for name, vt in VTABLES.items():
        hits = scan_for(core, vt)
        print("=" * 74)
        print(f"{name}  vtable {vt:#x}  -> {len(hits)} pointer(s)")
        print("=" * 74)
        for h in hits[:8]:
            print(f"\n  object-ish at {h:#x}")
            try:
                raw = bytes(core.uc.mem_read(h - 0x20, 0x80))
            except Exception:
                print("    (unreadable)")
                continue
            for off in range(0, len(raw), 8):
                at = h - 0x20 + off
                v = struct.unpack_from("<Q", raw, off)[0]
                if v == 0:
                    continue
                sel = " >>" if at == h else "   "
                tag = ""
                if core.base <= v < core.base + 0x100000000:
                    tag = f" -> {v - core.base:#x}"
                print(f"    {sel} {at:#x}: {v:#018x}{tag}")
        if not hits:
            print("  (none found)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
