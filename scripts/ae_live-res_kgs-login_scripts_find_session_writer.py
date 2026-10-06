#!/usr/bin/env python3
"""Find every STORE to the session global 0xa4ab6a8 and the mode global
0xa4ab6a0.  Also report which registrars fail.
"""
from __future__ import annotations

import os
import struct
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

TARGETS = {0xA4AB6A8: "session", 0xA4AB6A0: "mode"}


def imm_hi(i):
    v = (((i >> 5) & 0x7FFFF) << 2) | ((i >> 29) & 3)
    if v & (1 << 20):
        v -= 1 << 21
    return v << 12


def imm12(i):
    return (i >> 10) & 0xFFF


def main():
    with open(os.path.join(HERE, "apk_lab", "libUE4.so"), "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)

    hits = defaultdict(list)
    last = (None, None)
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        pc = TEXT_VADDR + idx * 4
        if (i & 0x80000000) and (i & 0x1F000000) == 0x10000000:
            last = (i & 0x1F, (pc & ~0xFFF) + imm_hi(i))
            continue
        if (i & 0x80000000) == 0 and (i & 0x1F000000) == 0x10000000:
            continue
        # STR xt, [xn, #imm] unsigned offset 64-bit -> 0xF9000000
        if (i & 0xFFC00000) == 0xF9000000:
            rn = (i >> 5) & 0x1F
            if last[0] == rn:
                a = last[1] + imm12(i) * 8
                if a in TARGETS:
                    hits[a].append((pc, "ADRP+STR"))
        # STP xt, xt2, [xn, #imm] -> 0xA9000000 (pre/post/unsigned variants)
        if (i & 0xFFC00000) == 0xA9000000 or \
           (i & 0xFFC00000) == 0xA9800000 or \
           (i & 0xFFC00000) == 0xAD000000:
            rn = (i >> 5) & 0x1F
            if last[0] == rn:
                a = last[1] + imm12(i) * 8
                if a in TARGETS:
                    hits[a].append((pc, "ADRP+STP"))
        # ADD imm
        if (i & 0xFFC00000) == 0x91000000:
            rn = (i >> 5) & 0x1F
            if last[0] == rn:
                a = last[1] + imm12(i)
                if a in TARGETS:
                    hits[a].append((pc, "ADRP+ADD"))
        # LDR xt, [xn, #imm]
        if (i & 0xFFC00000) == 0xF9400000:
            rn = (i >> 5) & 0x1F
            if last[0] == rn:
                a = last[1] + imm12(i) * 8
                if a in TARGETS:
                    hits[a].append((pc, "ADRP+LDR(read)"))

    for a, name in TARGETS.items():
        sites = hits.get(a, [])
        writers = [s for s in sites if "read" not in s[1]]
        print(f"\n{name} @ {a:#x}: {len(sites)} ref(s), "
              f"{len(writers)} WRITER(s)")
        for s, k in sites[:20]:
            print(f"    {s:#x}  {k}")

    # ---- registrar failures ---------------------------------------------
    print("\n" + "=" * 74)
    print("REGISTRAR RESULTS")
    print("=" * 74)
    core = OnlineCore(verbose=False)
    for fn in REGISTRARS:
        try:
            r = core.call(fn)
            print(f"  {fn:#x}: ok  x0={r.get('x0'):#x}")
        except Exception as e:
            print(f"  {fn:#x}: {type(e).__name__} {str(e)[:70]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
