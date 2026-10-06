#!/usr/bin/env python3
"""Every *.php script name that appears anywhere in the binary."""
from __future__ import annotations

import sys

PATH = r"apk_lab\libUE4.so"


def main() -> int:
    data = open(PATH, "rb").read()
    seen: set[str] = set()
    s = 0
    hits: list[tuple[int, str]] = []
    while True:
        i = data.find(b".php", s)
        if i < 0:
            break
        s = i + 4
        a = i
        while a > 0 and (32 <= data[a - 1] < 127):
            a -= 1
        b = data.find(b"\0", i)
        if b < 0:
            b = i + 60
        txt = data[a:min(b, a + 120)].decode("latin1")
        # trim to the token containing .php
        token = txt
        if " " in token:
            token = token.split(" ")[-1]
        if token not in seen and ".php" in token:
            seen.add(token)
            hits.append((a, token))
    for addr, t in sorted(hits):
        print(f"  {addr:#010x}  {t}")
    print(f"total {len(hits)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
