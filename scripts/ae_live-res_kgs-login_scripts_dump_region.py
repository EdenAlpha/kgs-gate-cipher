#!/usr/bin/env python3
"""Print the C-strings around a file offset (= vaddr for .rodata).

  python dump_region.py 0xbc9e40 0xb0
"""
from __future__ import annotations

import sys

PATH = r"apk_lab\libUE4.so"


def main() -> int:
    data = open(PATH, "rb").read()
    start = int(sys.argv[1], 16)
    length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x80
    blob = data[start:start + length]
    i = 0
    while i < len(blob):
        if blob[i] == 0:
            i += 1
            continue
        j = blob.find(b"\0", i)
        if j < 0:
            j = len(blob)
        s = blob[i:j]
        if all(32 <= c < 127 for c in s) and len(s) >= 3:
            print(f"  {start + i:#x}  {s.decode()}")
        i = j + 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
