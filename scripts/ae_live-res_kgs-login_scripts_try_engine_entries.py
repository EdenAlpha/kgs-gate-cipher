#!/usr/bin/env python3
"""Try the engine's own entry points and see if any initializes the online
command table (0xa4cff18)."""
from __future__ import annotations

import os
import struct
import sys
import time

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CANDS = [
    (0x2836D28, "nativeResumeMainInit"),
    (0x2830BF4, "nativeSetGlobalActivity"),
    (0x2830A60, "nativeSetObbFilePaths"),
    (0x2830E5C, "nativeOnActivityResult"),
    (0x2838070, "nativeSetAndroidVersionInformation"),
    (0x2837EC0, "nativeConsoleCommand"),
]
TBL = 0xA4CFF18


def tbl(core, B):
    try:
        raw = bytes(core.uc.mem_read(B + TBL, 12 * 8))
    except Exception:
        return []
    return [(i, struct.unpack_from("<Q", raw, i * 8)[0] - B)
            for i in range(12)
            if struct.unpack_from("<Q", raw, i * 8)[0]]


def main():
    for addr, name in CANDS:
        print("\n" + "#" * 74)
        print(f"# {name} {addr:#x}")
        print("#" * 74)
        core = OnlineCore(verbose=False)
        core.install_netsplice()
        for fn in REGISTRARS:
            try:
                core.call(fn)
            except Exception:
                pass
        core.call(0x7CDA280, timeout_s=60)
        B = core.base
        before = tbl(core, B)
        print(f"  before: {len(before)} entries")
        try:
            r = core.call(addr, timeout_s=30, max_insns=8_000_000)
            print(f"  -> err={r.get('error')} x0={r.get('x0'):#x}")
        except Exception as e:
            print(f"  -> {type(e).__name__}: {str(e)[:60]}")
        after = tbl(core, B)
        print(f"  after : {len(after)} entries")
        for i, v in after[:6]:
            print(f"      [{i:2d}] {v:#x}")
        if after and not before:
            print(f"  *** {name} POPULATED THE TABLE ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
