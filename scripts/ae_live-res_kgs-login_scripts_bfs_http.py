#!/usr/bin/env python3
"""Backward BFS from the HTTP functions to find who eventually calls them,
and whether the chain reaches the session methods (0x7cdb..0x7ce1).
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict, deque

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
FDE = os.path.join(HERE, "funcs_eh.txt")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

SEEDS = {0x7D038C8: "http_post_routine", 0x7D0C06C: "gateinfo_sender"}

SESS = {0x7CDA184, 0x7CDA1F8, 0x7CDB974, 0x7CDB9D0, 0x7CE1A48,
        0x7CE1ACC, 0x7CDBA60, 0x7CDC3D8, 0x7CDC414, 0x7CDC6E8,
        0x7CDCA20, 0x7CDCAD4, 0x7CDCAB4, 0x7CE1860, 0x7CE1974,
        0x7CE1480, 0x7CE157C, 0x7CE158C, 0x7CE1594, 0x7CE159C,
        0x7CE15A4, 0x7CE15AC, 0x7CDCAF4, 0x7CE1334, 0x7CE1450,
        0x7CDD7CC, 0x7CDD70C, 0x7CDD790, 0x7CDD7AC, 0x7CDD7B4}


def load_fde():
    arr = []
    with open(FDE, encoding="utf-8") as f:
        for line in f:
            p = line.split()
            arr.append((int(p[0], 16), int(p[1], 16)))
    return arr


def enclosing(arr, addr):
    lo, hi = 0, len(arr) - 1
    best = None
    while lo <= hi:
        m = (lo + hi) // 2
        if arr[m][0] <= addr:
            best = m
            lo = m + 1
        else:
            hi = m - 1
    if best is None:
        return None
    a, b = arr[best]
    return (a, b) if a <= addr < b else None


def main():
    fde = load_fde()
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)

    bl = defaultdict(list)
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        if (i & 0xFC000000) == 0x94000000:
            imm = i & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = TEXT_VADDR + idx * 4
            bl[pc + (imm << 2)].append(pc)

    # BFS
    prev = {}
    q = deque()
    for s in SEEDS:
        q.append(s)
        prev[s] = None
    found_sess = set()
    for _ in range(8):
        if not q:
            break
        cur = q.popleft()
        for site in bl.get(cur, []):
            e = enclosing(fde, site)
            fn = e[0] if e else None
            if fn is None or fn in prev:
                continue
            prev[fn] = cur
            q.append(fn)
            if fn in SESS:
                found_sess.add(fn)

    print("functions reachable backwards from the HTTP seeds:")
    for fn, tgt in prev.items():
        if fn in SEEDS:
            continue
        mark = "  <== SESSION METHOD" if fn in SESS else ""
        print(f"  {fn:#x}  <- {tgt}{mark}")

    print(f"\nsession methods reached: {len(found_sess)}")
    for f in sorted(found_sess):
        print(f"  {f:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
