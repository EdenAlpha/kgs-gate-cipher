#!/usr/bin/env python3
"""List function starts/ends inside an address range.

  python list_fns.py 0xSTART 0xEND
"""
from __future__ import annotations

import re
import sys

LO = int(sys.argv[1], 16)
HI = int(sys.argv[2], 16)

rows = []
for line in open("funcs_eh.txt", encoding="utf-8"):
    m = re.match(r"0x([0-9a-fA-F]+) 0x([0-9a-fA-F]+)", line.strip())
    if not m:
        continue
    s = int(m.group(1), 16)
    e = int(m.group(2), 16)
    if LO <= s < HI:
        rows.append((s, e))

rows.sort()
for s, e in rows:
    print(f"  {s:#010x} .. {e:#010x}   size {e - s:#x}")
print(f"total {len(rows)}")
