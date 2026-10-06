#!/usr/bin/env python3
"""Find writers of the channel-holder globals the gRPC gate reads.

0x7dc2578 reads:
    x20 = page 0xa4b2000
    x21 = *(x20 + 0x3e8)   = 0xa4b23e8  -> channel-holder pointer
    str at (x20 + 0x3f0)  = 0xa4b23f0  -> channel target string

Both are reached as ADRP(0xa4b2000) + fixed offset, so search for that page
and the offsets, and report which function *stores* to them.
"""
from __future__ import annotations

import bisect
import os
import re
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
HERE = os.path.dirname(os.path.abspath(__file__))
FDE = os.path.join(HERE, "funcs_eh.txt")
TEXT_OFF = 0x28253C0
TEXT_VADDR = 0x28293C0
TEXT_SIZE = 0x630BE48

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


def stext(a, n=60):
    try:
        b = data[a:a + n].split(b"\x00")[0]
        return b.decode("latin1", "replace") if b else ""
    except Exception:
        return ""


PAGE = 0xA4B2000
WANT_OFF = (0x3D8, 0x3E0, 0x3E8, 0x3F0, 0x3F8)
text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
pending = {}
found = {}
for off in range(0, len(text), 4):
    w = struct.unpack_from("<I", text, off)[0]
    pc = TEXT_VADDR + off
    # ADRP
    if (w & 0x9F000000) == 0x90000000:
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        v = (immhi << 2) | immlo
        if v & (1 << 20):
            v -= 1 << 21
        base = (pc & ~0xFFF) + (v << 12)
        pending[w & 0x1F] = base
        continue
    # LDR/STR (immediate, unsigned offset 0..4095*scale)
    if (w & 0x3B000000) in (0x39000000, 0x39000000 | 0x20000000) or \
       (w & 0xFFC00000) in (0xF9000000, 0xF9400000):
        rn = (w >> 5) & 0x1F
        if rn in pending and pending[rn] == PAGE:
            imm12 = (w >> 10) & 0xFFF
            scale = 8 if (w >> 30) & 1 else 4
            if (w >> 22) & 1:        # 64-bit
                scale = 8
            tgt = PAGE + imm12 * scale
            if (tgt - PAGE) in WANT_OFF:
                store = (w >> 22) & 1
                op = "STR" if store else "LDR"
                found.setdefault(tgt, []).append((op, pc))
        pending.pop(w & 0x1F, None)
        continue
    pending.pop(w & 0x1F, None)

for tgt in sorted(found):
    hits = found[tgt]
    stores = [h for h in hits if h[0] == "STR"]
    print("=== %#x (page %#x + %#x): %d refs, %d stores ==="
          % (tgt, PAGE, tgt - PAGE, len(hits), len(stores)), flush=True)
    seen = set()
    for op, pc in hits:
        fs, fe = fn_of(pc)
        key = (op, fs)
        if key in seen:
            continue
        seen.add(key)
        print("   %s pc=%#x  fn %#x..%#x (%dB)  str=%r"
              % (op, pc, fs, fe, fe - fs, stext(fs)), flush=True)
    print(flush=True)
