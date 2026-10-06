#!/usr/bin/env python3
"""State 9 needs *(0xa4cff20) != NULL and that_obj->[0x118] != NULL.
0xa4cff18 is a pointer table (the env table 0xa4cff68 sits at +0x50).
Check what's there at runtime."""
from __future__ import annotations

import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

TBL = 0xA4CFF18


def main():
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    B = core.base

    print(f"pointer table @ {TBL:#x} (16 entries)")
    print("=" * 74)
    try:
        raw = bytes(core.uc.mem_read(B + TBL, 16 * 8))
    except Exception as e:
        print(f"  unreadable: {type(e).__name__}")
        return 1
    for i in range(16):
        v = struct.unpack_from("<Q", raw, i * 8)[0]
        mark = ""
        if i == 1:
            mark = "   <== state 9 needs this"
        elif i == 10:
            mark = "   (env table region)"
        if v == 0:
            print(f"  [{i:2d}] +{i*8:#05x}  (null){mark}")
        else:
            print(f"  [{i:2d}] +{i*8:#05x}  {v:#018x}{mark}")

    # is array[1] populated?  check its [0x118]
    v1 = struct.unpack_from("<Q", raw, 1 * 8)[0]
    if v1:
        print(f"\narray[1] = {v1:#x} (vaddr {v1 - B:#x})")
        try:
            p = struct.unpack("<Q", bytes(core.uc.mem_read(v1 + 0x118, 8)))[0]
            print(f"  array[1]->[0x118] = {p:#x}")
        except Exception as e:
            print(f"  array[1]->[0x118] unreadable: {type(e).__name__}")
    else:
        print(f"\n*** array[1] is NULL -- state 9 will always bail ***")
        print("    -> the online command table is not initialized")
    return 0


if __name__ == "__main__":
    sys.exit(main())
