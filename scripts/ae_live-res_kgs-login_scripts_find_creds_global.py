#!/usr/bin/env python3
"""Who writes the gRPC credentials global at 0xa40b038?

0x6777868 (the game's args builder) is a one-liner:
    adrp x8, #0xa40b000 ; ldr x0, [x8, #0x38] ; ret
i.e. return *(0xa40b038) -- the gRPC channel-credentials object. Every
higher-level gRPC entry point calls it and bails when it is NULL, which is
why the task step returned 0 immediately.

Find the function that stores into it, print it, and the strings it uses --
that tells us which constructor to call.
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


PAGE, OFF = 0xA40B000, 0x38
text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
pending = {}
found = []
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
                found.append(("STR" if (w >> 22) & 1 else "LDR", pc))
        pending.pop(w & 0x1F, None)
        continue
    if (w & 0xFF800000) == 0x91000000:
        rn = (w >> 5) & 0x1F
        if rn in pending and pending[rn] + ((w >> 10) & 0xFFF) * (
                12 if (w >> 22) & 1 else 1) == PAGE + OFF:
            found.append(("ADD-STR", pc))
        pending.pop(w & 0x1F, None)
        continue
    pending.pop(w & 0x1F, None)

print("=== refs to %#x : %d ===" % (PAGE + OFF, len(found)), flush=True)
seen = set()
for op, pc in found:
    fs, fe = fn_of(pc)
    if (op, fs) in seen:
        continue
    seen.add((op, fs))
    print("  %-8s pc=%#x  fn %#x..%#x (%dB)  str=%r"
          % (op, pc, fs, fe, fe - fs, stext(fs)), flush=True)
    if op == "STR":
        lo = max(fs, pc - 0x60)
        for a in range(lo, min(fe, pc + 0x20), 4):
            pass
