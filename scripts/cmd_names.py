#!/usr/bin/env python3
"""cmd_names.py -- list every CMD_* command name in .rodata.

Rebuilt 2026-10-10 (original destroyed by temp cleanup).
READ-ONLY.
"""
import re
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from xref2 import Elf  # noqa: E402

PAT = re.compile(r"CMD_[A-Z0-9_]+")
INTEREST = re.compile(
    r"HB|HEART|BEAT|KEEP|ALIVE|PING|POLL|PROGRESS|STATUS|REPORT|"
    r"WATCH|NOTICE|NOTIFY|UPDATE|SEND_(GAME|MATCH)|RENEW|REFRESH|TOUCH",
    re.I)


def main():
    e = Elf(sys.argv[1])
    _, _, _, addr, to, ts = e.sec(".rodata")
    raw = e.read(to, ts)
    names = set(m.group(0) for m in PAT.finditer(raw.decode("latin1")))
    names = {n for n in names if len(n) > 4}
    print("total CMD_* names: %d" % len(names))
    hit = sorted(n for n in names if INTEREST.search(n))
    print("=== %d heartbeat-shaped ===" % len(hit))
    for n in hit:
        print("  %s" % n)
    if "--all" in sys.argv:
        print("=== all ===")
        for n in sorted(names):
            print("  %s" % n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
