#!/usr/bin/env python3
"""Find functions that read BOTH the cmd-name field (+0x138) and the
script-name field (+0x170) of a command object -- i.e. the routine that
turns a Cmd* object into an outgoing request."""
from __future__ import annotations

import bisect
import re
import struct

PATH = r"apk_lab\libUE4.so"
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(PATH, "rb").read()

starts = []
recs = []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if not m:
        continue
    starts.append(int(m.group(1), 16))
    recs.append((int(m.group(1), 16), int(m.group(2), 16)))


def insn(a):
    off = TEXT_OFF + (a - TEXT_V)
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def fn_of(a):
    i = bisect.bisect_right(starts, a) - 1
    if i >= 0 and starts[i] <= a < recs[i][1]:
        return recs[i][0], recs[i][1]
    return None


def collect(op, imm):
    """all instructions of the shape op [x, #imm] grouped by function"""
    target = op | (imm << 10)
    out = {}
    for a in range(TEXT_V, TEXT_V + TEXT_SIZE, 4):
        if (insn(a) & 0xFFFFFC00) != target:
            continue
        f = fn_of(a)
        if f:
            out.setdefault(f[0], []).append(a)
    return out


# LDRB (unsigned imm), LDR x (unsigned imm), LDR w (unsigned imm)
variants = {
    "LDRB": 0x39400000,
    "LDRx": 0xF9400000,
    "LDRw": 0xB9400000,
}

found = {}
for name, op in variants.items():
    for off, tag in ((0x138, "138"), (0x170, "170")):
        for fn, sites in collect(op, off).items():
            found.setdefault(fn, {}).setdefault(tag, []).append(
                (name, off, sites))

both = {fn: v for fn, v in found.items() if "138" in v and "170" in v}
print(f"total fns touching either field: {len(found)}")
print(f"fns touching BOTH: {len(both)}\n")

for fn in sorted(both):
    i = bisect.bisect_right(starts, fn) - 1
    print(f"  fn {fn:#x}..{recs[i][1]:#x} size {recs[i][1] - fn:#x}")
    for tag in ("138", "170"):
        for name, off, sites in both[fn][tag]:
            print(f"      +{off:#x} via {name} at "
                  f"{', '.join(hex(s) for s in sites[:6])}")
