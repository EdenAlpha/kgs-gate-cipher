#!/usr/bin/env python3
"""Print printable-ASCII runs inside a byte range of libUE4.so.

  python strruns.py 0xbef000 0xbef800 [minlen]
"""
from __future__ import annotations

import sys

PATH = r"apk_lab\libUE4.so"


def main() -> int:
    lo = int(sys.argv[1], 16)
    hi = int(sys.argv[2], 16)
    minlen = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    data = open(PATH, "rb").read()
    seg = data[lo:hi]
    out = []
    cur = bytearray()
    start = 0
    for i, c in enumerate(seg):
        if 32 <= c < 127:
            if not cur:
                start = i
            cur.append(c)
        else:
            if len(cur) >= minlen:
                out.append((lo + start, bytes(cur)))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append((lo + start, bytes(cur)))
    for a, s in out:
        print(f"  {a:#09x}  {s.decode('latin1')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
