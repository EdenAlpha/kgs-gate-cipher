#!/usr/bin/env python3
"""Reverse relocation map: who points at a given VA?

Earlier every string xref came back EMPTY because the strings are reached
through relocated pointer tables (all-zero in the file).  LIEF gave us the
1.33M relocations, so we can now invert them:

    R_AARCH64_RELATIVE  addend == TARGET  ->  the slot at `offset` holds a
    pointer to TARGET.

Then find the .text code that materialises the SLOT address (ADRP+ADD/LDR),
which IS statically visible.  That is the function using the string.

    python rev_reloc.py 0xVA [0xVA ...] [--funcs]
"""
from __future__ import annotations

import bisect
import os
import re
import struct
import sys

import numpy as np

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
NPZ = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
       r"\peerlink_work\apk_lab\analysis\packed_relocs.npz")
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(SO, "rb").read()
starts, recs = [], []
for line in open(r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
                 r"\peerlink_work\funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if m:
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        starts.append(s)
        recs.append((s, e))


def fn_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return recs[i] if i >= 0 and starts[i] <= a < recs[i][1] else (0, 0)


def load_relocs():
    pr = np.load(NPZ, allow_pickle=True)
    off = pr["offset"]
    rtype = pr["rtype"]
    add = pr["addend"]
    m = rtype == 1027                       # R_AARCH64_RELATIVE
    return off[m].astype(np.int64), add[m].astype(np.int64)


W = np.frombuffer(data, dtype="<u4", count=TEXT_SIZE // 4,
                  offset=TEXT_OFF).astype(np.int64)
PCS = TEXT_V + np.arange(len(W), dtype=np.int64) * 4
ADRP_MASK = (W & 0x9F000000) == 0x90000000
_IMMLO = (W >> 29) & 3
_IMMHI = (W >> 5) & 0x7FFFF
_IMM = ((_IMMHI << 2) | _IMMLO) << 12
_IMM = np.where(_IMM & (1 << 32), _IMM - (1 << 33), _IMM)
PAGE = ((PCS & ~np.int64(0xFFF)) + _IMM)


def xrefs_to_slot(slot: int, maxn: int = 12):
    """ADRP+ADD/LDR that materialise `slot`."""
    want = slot & ~0xFFF
    off = slot & 0xFFF
    hits = []
    idx = np.nonzero(ADRP_MASK & (PAGE == want))[0]
    for i in idx:
        rn = int((W[i] >> 5) & 31)
        for k in (1, 2, 3):
            j = i + k
            if j >= len(W):
                break
            w2 = int(W[j])
            if ((w2 >> 5) & 31) != rn:
                continue
            # ADD xD, xN, #imm
            if (w2 & 0xFFC00000) == 0x91000000:
                i2 = (w2 >> 10) & 0xFFF
                if (w2 >> 22) & 1:
                    i2 <<= 12
                if i2 == off:
                    hits.append((int(PCS[i]), int(PCS[j]), "ADD"))
            # LDR xD, [xN, #imm]
            if (w2 & 0xFFC00000) == 0xF9400000:
                i2 = ((w2 >> 10) & 0xFFF) * 8
                if i2 == off:
                    hits.append((int(PCS[i]), int(PCS[j]), "LDR"))
        if len(hits) >= maxn:
            break
    return hits


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show_fn = "--funcs" in sys.argv
    targets = [int(a, 16) for a in args]
    if not targets:
        print("usage: rev_reloc.py 0xVA [...]")
        return 1

    roff, radd = load_relocs()
    print(f"loaded {len(roff):,} RELATIVE relocs\n", flush=True)

    order = np.argsort(radd)
    radd_s = radd[order]
    roff_s = roff[order]

    for t in targets:
        lo = np.searchsorted(radd_s, t, "left")
        hi = np.searchsorted(radd_s, t, "right")
        slots = [int(x) for x in roff_s[lo:hi]]
        # also show the string itself if printable
        s = ""
        try:
            raw = bytes(data[t:t + 80]).split(b"\x00")[0]
            if raw and all(32 <= c < 127 for c in raw):
                s = raw.decode()
        except Exception:
            pass
        print(f"=== TARGET {t:#x}  {s!r}   -> {len(slots)} pointer slot(s)",
              flush=True)
        for slot in slots[:20]:
            print(f"    slot at {slot:#x}  (in "
                  f"{'rodata' if slot < TEXT_V else 'data'})", flush=True)
            for a, b, kind in xrefs_to_slot(slot):
                s2, e2 = fn_of(b)
                extra = f"   fn {s2:#x}..{e2:#x}" if show_fn or s2 else ""
                print(f"        {kind} {a:#x} / {b:#x}{extra}", flush=True)
        if len(slots) > 20:
            print(f"    ... {len(slots) - 20} more slots", flush=True)
        print(flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
