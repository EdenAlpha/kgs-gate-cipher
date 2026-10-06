#!/usr/bin/env python3
"""Find gRPC's OWN poller and call it, so the live channel dials for real.

The channel is alive (state=2) but idle: gRPC never dials until its pollset
runs. The binary carries gRPC's posix iomgr:
    'ev_posix.cc'  'pollset_work'  'grpc_poll_strategy'  'POLLOUT'
so the poller is in there, not an import. Locate the function that owns
'pollset_work' (via its assert string, like we did for the gRPC client) and
also the 'epoll_wait'/'ev_epoll' entry, then call it in a loop.
"""
from __future__ import annotations

import bisect
import os
import re
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
HERE = os.path.dirname(os.path.abspath(__file__))
FDE = os.path.join(HERE, "funcs_eh.txt")
TEXT_OFF, TEXT_VADDR, TEXT_SIZE = 0x28253C0, 0x28293C0, 0x630BE48

data = open(SO, "rb").read()
starts, recs = [], []
for line in open(FDE, encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if m:
        starts.append(int(m.group(1), 16))
        recs.append((int(m.group(1), 16), int(m.group(2), 16)))


def fn_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return recs[i] if i >= 0 and starts[i] <= a < recs[i][1] else (0, 0)


def stext(a, n=80):
    try:
        b = data[a:a + n].split(b"\x00")[0]
        return b.decode("latin1", "replace") if b else ""
    except Exception:
        return ""


def adrp(i, pc):
    if (i & 0x9F000000) != 0x90000000:
        return None
    immlo = (i >> 29) & 3
    immhi = (i >> 5) & 0x7FFFF
    v = (immhi << 2) | immlo
    if v & (1 << 20):
        v -= 1 << 21
    return (pc & ~0xFFF) + (v << 12), i & 0x1F


def add_imm(i):
    if (i & 0xFF800000) != 0x91000000:
        return None
    return (i & 0x1F), (i >> 5) & 0x1F, ((i >> 10) & 0xFFF) * (
        12 if (i >> 22) & 1 else 1)


text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]


def find_refs(target):
    page = target & ~0xFFF
    pend = {}
    hits = []
    for off in range(0, len(text), 4):
        w = struct.unpack_from("<I", text, off)[0]
        pc = TEXT_VADDR + off
        r = adrp(w, pc)
        if r:
            base, rd = r
            pend[rd] = base
            if base == page:
                hits.append(("ADRP", pc))
            continue
        a = add_imm(w)
        if a:
            rd, rn, imm = a
            if rn in pend and pend[rn] + imm == target:
                hits.append(("ADRP+ADD", pc))
            pend.pop(rd, None)
    return hits


for needle in (b"pollset_work", b"ev_posix", b"grpc_poll_strategy",
               b"POLLOUT", b"epoll_wait"):
    idx = data.find(needle)
    if idx < 0:
        print("%-20s not found" % needle.decode())
        continue
    st = idx
    while st > 0 and 32 <= data[st - 1] < 127:
        st -= 1
    va = st
    print("=== %r at %#x (va) ===" % (data[st:idx + 8], va), flush=True)
    for kind, pc in find_refs(va)[:10]:
        fs, fe = fn_of(pc)
        print("    %-9s %#012x  fn %#012x..#%012x  %r"
              % (kind, pc, fs, fe, stext(fs)), flush=True)
