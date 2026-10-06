#!/usr/bin/env python3
"""Literal-byte xref finder (case sensitive) in libUE4.so.

  python find_lit.py cmd_name [more...]
"""
from __future__ import annotations

import sys

PATH = r"apk_lab\libUE4.so"


def main() -> int:
    data = open(PATH, "rb").read()
    for arg in sys.argv[1:]:
        pat = arg.encode("utf-8")
        s = 0
        hits = []
        while True:
            i = data.find(pat, s)
            if i < 0:
                break
            hits.append(i)
            s = i + 1
            if len(hits) > 8:
                break
        print(f"{arg!r:34s} {[hex(h) for h in hits]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
