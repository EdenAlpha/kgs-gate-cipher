#!/usr/bin/env python3
"""Try calling each candidate writer and see if the SM's command table
(0xa4cff18) gets populated."""
from __future__ import annotations

import os
import struct
import sys
import time

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CANDS = [0x8132360, 0x813C664, 0x813C820, 0x812738C, 0x8137F9C]
TBL = 0xA4CFF18


def dump_tbl(core, B):
    try:
        raw = bytes(core.uc.mem_read(B + TBL, 12 * 8))
    except Exception:
        return []
    out = []
    for i in range(12):
        v = struct.unpack_from("<Q", raw, i * 8)[0]
        if v:
            out.append((i, v - B if B <= v < B + 0x100000000 else v))
    return out


def main():
    for cand in CANDS:
        print("\n" + "#" * 74)
        print(f"# candidate {cand:#x}")
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
        before = dump_tbl(core, B)
        print(f"  table before: {len(before)} entries")
        try:
            r = core.call(cand, timeout_s=40, max_insns=10_000_000)
            print(f"  -> err={r.get('error')} x0={r.get('x0'):#x}")
        except Exception as e:
            print(f"  -> {type(e).__name__}: {str(e)[:60]}")
        after = dump_tbl(core, B)
        print(f"  table after : {len(after)} entries")
        for i, v in after[:8]:
            print(f"      [{i:2d}] {v:#x}")
        if after:
            print(f"  *** TABLE POPULATED by {cand:#x} ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
