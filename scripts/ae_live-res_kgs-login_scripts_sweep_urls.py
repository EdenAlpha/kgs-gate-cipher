#!/usr/bin/env python3
"""Exhaustive sweep: every absolute URL and every *.konami.net host in the file."""
from __future__ import annotations

import sys

PATH = r"apk_lab\libUE4.so"


def strings_from(blob: bytes, off: int, back: int = 0) -> list[tuple[int, str]]:
    """Return (addr, text) for printable runs ending at/after off."""
    out = []
    i = max(0, off - back)
    while i < len(blob):
        if blob[i] == 0 or not (32 <= blob[i] < 127):
            i += 1
            continue
        j = blob.find(b"\0", i)
        if j < 0:
            j = len(blob)
        s = blob[i:j]
        if all(32 <= c < 127 for c in s) and len(s) >= 4:
            out.append((i, s.decode()))
        i = j + 1
    return out


def main() -> int:
    data = open(PATH, "rb").read()
    seen: set[int] = set()
    for pat in (b"http://", b"https://"):
        s = 0
        while True:
            i = data.find(pat, s)
            if i < 0:
                break
            s = i + 1
            # find enclosing NUL-delimited string
            a = i
            while a > 0 and 32 <= data[a - 1] < 127:
                a -= 1
            b = data.find(b"\0", i)
            if b < 0:
                b = i + 80
            key = a
            if key in seen:
                continue
            seen.add(key)
            txt = data[a:min(b, a + 200)].decode("latin1")
            print(f"URL   {a:#010x}  {txt}")
    print()
    for pat in (b".konami.net", b".konami.com"):
        s = 0
        n = 0
        while True:
            i = data.find(pat, s)
            if i < 0:
                break
            s = i + 1
            n += 1
            a = i
            while a > 0 and (32 <= data[a - 1] < 127):
                a -= 1
            b = data.find(b"\0", i)
            if b < 0:
                b = i + 80
            txt = data[a:min(b, a + 160)].decode("latin1")
            print(f"HOST  {a:#010x}  {txt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
