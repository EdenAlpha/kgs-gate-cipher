#!/usr/bin/env python3
"""Scan .text for a specific immediate, so we can find field readers cheaply.

  python find_imm.py 0x171 --range 0x7600000 0x7d00000

Useful immediates:
    0x171  data start of the short string at +0x170 ("CmdGetServerEnv.php")
    0x139  data start of the short string at +0x138 ("CMD_GET_SERVER_ENV")
Prints the enclosing function and the instruction.
"""
from __future__ import annotations

import bisect
import re
import struct
import sys

PATH = r"apk_lab\libUE4.so"
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(PATH, "rb").read()

starts, recs = [], []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if not m:
        continue
    s, e = int(m.group(1), 16), int(m.group(2), 16)
    starts.append(s)
    recs.append((s, e))


def insn(a: int) -> int:
    off = TEXT_OFF + (a - TEXT_V)
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def decode(w: int):
    """-> (kind, base, value) when an immediate matches a load/add."""
    base = w & 31
    if base == 31:
        return None
    # ADD (immediate), 64-bit, shift 0
    if (w & 0xFF800000) == 0x91000000 and (w & 0x400000) == 0:
        return ("add", base, (w >> 10) & 0xFFF)
    # ADD (immediate), 32-bit
    if (w & 0xFF800000) == 0x11000000 and (w & 0x400000) == 0:
        return ("add32", base, (w >> 10) & 0xFFF)
    # LDRB unsigned offset
    if (w & 0xFFC00000) == 0x39400000:
        return ("ldrb", base, (w >> 10) & 0xFFF)
    # LDRH unsigned offset
    if (w & 0xFFC00000) == 0x79400000:
        return ("ldrh", base, (w >> 10) & 0xFFF)
    # LDR X unsigned offset (scaled 8)
    if (w & 0xFFC00000) == 0xF9400000:
        return ("ldrx", base, ((w >> 10) & 0xFFF) * 8)
    # LDR W unsigned offset (scaled 4)
    if (w & 0xFFC00000) == 0xB9400000:
        return ("ldrw", base, ((w >> 10) & 0xFFF) * 4)
    return None


def main() -> int:
    args = sys.argv[1:]
    rng = (0, TEXT_V + TEXT_SIZE)
    if "--range" in args:
        i = args.index("--range")
        rng = (int(args[i + 1], 16), int(args[i + 2], 16))
        args = args[:i]
    targets = [int(a, 16) for a in args]
    for t in targets:
        print(f"=== immediate {t:#x} ===")
        fns: dict[int, list[int]] = {}
        for a in range(TEXT_V, TEXT_V + TEXT_SIZE, 4):
            if not rng[0] <= a < rng[1]:
                continue
            r = decode(insn(a))
            if not r or r[2] != t:
                continue
            i = bisect.bisect_right(starts, a) - 1
            fn = recs[i][0] if i >= 0 and starts[i] <= a < recs[i][1] else 0
            fns.setdefault(fn, []).append(a)
        for fn in sorted(fns):
            addrs = fns[fn]
            i = bisect.bisect_right(starts, fn)
            end = recs[i - 1][1] if i > 0 else fn
            print(f"  {fn:#x}..{end:#x}  {len(addrs):3d}  "
                  f"{[hex(x) for x in addrs[:6]]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
