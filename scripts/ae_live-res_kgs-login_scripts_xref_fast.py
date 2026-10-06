#!/usr/bin/env python3
"""Fast ADRP+ADD xref scan (numpy, not a Python loop).

    python xref_fast.py 0xADDR [0xADDR ...]

Also reports raw aarch64 `svc` syscalls (getrandom = 278, openat = 56),
which never appear in the import table and so have been invisible.
"""
from __future__ import annotations

import bisect
import re
import struct
import sys

import numpy as np

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(SO, "rb").read()
starts, recs = [], []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if m:
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        starts.append(s)
        recs.append((s, e))


def fn_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return recs[i] if i >= 0 and starts[i] <= a < recs[i][1] else (0, 0)


def xref(target: int):
    w = np.frombuffer(data, dtype="<u4", count=TEXT_SIZE // 4,
                      offset=TEXT_OFF).astype("<u8")
    pcs = (TEXT_V + np.arange(len(w), dtype="<u8") * 4)

    adrp = (w & 0x9F000000) == 0x90000000
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    imm = np.where(imm & (1 << 32), imm - (1 << 33), imm)
    page = (pcs & ~np.uint64(0xFFF)) + imm.astype("<u8")

    want = target & ~0xFFF
    off = target & 0xFFF
    hits = []
    for i in np.nonzero(adrp & (page == want))[0]:
        rn = int((w[i] >> 5) & 31)
        for k in (1, 2, 3):
            j = i + k
            if j >= len(w):
                break
            w2 = int(w[j])
            if (w2 & 0xFFC003E0) != 0x91000000:      # ADD xD, xN, #imm
                continue
            if ((w2 >> 5) & 31) != rn:
                continue
            i2 = (w2 >> 10) & 0xFFF
            if (w2 >> 22) & 1:
                i2 <<= 12
            if i2 == off:
                hits.append((int(pcs[i]), int(pcs[j]), (w2 & 31)))
    return hits


def main() -> int:
    for arg in sys.argv[1:]:
        t = int(arg, 16)
        print(f"=== xrefs to {t:#x}")
        for a, b, rd in xref(t):
            s, e = fn_of(b)
            print(f"    adrp {a:#x}  add x{rd} {b:#x}   fn {s:#x}..{e:#x}")

    # raw syscalls
    print("\n=== raw `svc #0` immediates (aarch64 syscall numbers) ===")
    w = np.frombuffer(data, dtype="<u4", count=TEXT_SIZE // 4,
                      offset=TEXT_OFF)
    pcs = TEXT_V + np.arange(len(w), dtype="<u8") * 4
    svc = np.nonzero(w == np.uint32(0xD4000001))[0]
    NAME = {278: "getrandom", 56: "openat", 63: "read", 57: "close",
            62: "lseek", 64: "write", 78: "readlinkat", 17: "gettimeofday",
            113: "clock_gettime", 222: "mmap", 215: "munmap", 214: "brk",
            93: "exit", 94: "exit_group", 124: "sched_yield",
            98: "futex", 99: "set_robust_list", 226: "mprotect",
            233: "madvise", 220: "clone", 172: "getpid", 167: "prctl"}
    counts = {}
    for i in svc:
        # look back a few instructions for MOVZ/MOVK into x8
        nr = None
        for k in range(1, 8):
            j = i - k
            if j < 0:
                break
            w2 = int(w[j])
            if (w2 & 0xFF80001F) == 0xD2800008:      # MOVZ x8, #imm
                nr = (w2 >> 5) & 0xFFFF
                break
            if (w2 & 0xFF80001F) == 0xF2800008:      # MOVK x8, #imm, lsl 16
                nr = (((w2 >> 5) & 0xFFFF) << 16)
        key = NAME.get(nr, f"nr={nr}")
        counts[key] = counts.get(key, 0) + 1
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {k:18s} x{v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
