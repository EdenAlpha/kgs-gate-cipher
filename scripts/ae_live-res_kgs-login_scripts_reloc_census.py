#!/usr/bin/env python3
"""Census of dynamic relocations by type (which classes exist, how many).

If the harness loader skips a whole class (e.g. IRELATIVE), the broken vtable
slots are explained and the fix is bounded.  Read-only, fast.
"""
from __future__ import annotations

import lief

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")


def main() -> int:
    b = lief.parse(SO)
    counts: dict = {}
    examples: dict = {}
    for r in b.dynamic_relocations:
        t = r.type
        counts[t] = counts.get(t, 0) + 1
        if t not in examples and r.has_symbol:
            examples[t] = (hex(r.address), r.symbol.name[:60])
    print("total dynamic relocations:", len(b.dynamic_relocations))
    for t in sorted(counts, key=lambda x: int(x)):
        print("  type=%-6s count=%-8d e.g=%s" % (t, counts[t],
                                                 examples.get(t, "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
