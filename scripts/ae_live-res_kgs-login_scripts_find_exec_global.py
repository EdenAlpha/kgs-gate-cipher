#!/usr/bin/env python3
"""Find the writer of the gRPC executor singleton at 0xa4cfa40.

0x81306e8 is a one-liner:  return *(0xa4cfa40)
0x812cf98 (the channel init) branches on it:
    non-null -> state 8 then 9  (DEAD - "no executor, cannot connect")
    null     -> state 2, +0x51 = 1, then 0x7b095f4 / 0x81309e4 (LIVE)
So a null here is why every channel we create is born dead. Find who
populates it and call that.
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


def stext(a, n=70):
    try:
        b = data[a:a + n].split(b"\x00")[0]
        return b.decode("latin1", "replace") if b else ""
    except Exception:
        return ""


PAGE, OFF = 0xA4CF000, 0xA40
text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
pending = {}
hits = []
for off in range(0, len(text), 4):
    w = struct.unpack_from("<I", text, off)[0]
    pc = TEXT_VADDR + off
    if (w & 0x9F000000) == 0x90000000:
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        v = (immhi << 2) | immlo
        if v & (1 << 20):
            v -= 1 << 21
        pending[w & 0x1F] = (pc & ~0xFFF) + (v << 12)
        continue
    if (w & 0xFFC00000) in (0xF9000000, 0xF9400000):
        rn = (w >> 5) & 0x1F
        if rn in pending and pending[rn] == PAGE:
            imm12 = (w >> 10) & 0xFFF
            scale = 8 if ((w >> 22) & 1 or (w >> 30) & 1) else 4
            if imm12 * scale == OFF:
                hits.append(("STR" if (w >> 22) & 1 else "LDR", pc))
        pending.pop(w & 0x1F, None)
        continue
    if (w & 0xFF800000) == 0x91000000:
        rn = (w >> 5) & 0x1F
        if rn in pending and pending[rn] + ((w >> 10) & 0xFFF) * (
                12 if (w >> 22) & 1 else 1) == PAGE + OFF:
            hits.append(("ADD-STR", pc))
        pending.pop(w & 0x1F, None)
        continue
    pending.pop(w & 0x1F, None)

print("=== refs to %#x ===" % (PAGE + OFF), flush=True)
seen = set()
for op, pc in hits:
    fs, fe = fn_of(pc)
    if (op, fs) in seen:
        continue
    seen.add((op, fs))
    print("  %-8s pc=%#012x  fn %#012x..#%012x (%dB)  str=%r"
          % (op, pc, fs, fe, fe - fs, stext(fs)), flush=True)
