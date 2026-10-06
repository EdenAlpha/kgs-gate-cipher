#!/usr/bin/env python3
"""What config tokens / endpoints does the binary itself carry?

GateInfo went out with `version: "dt270"` -- a build token the server can
check.  If the binary holds a *set* of such tokens, or a second endpoint for
the gate, that is a lead we have not used.

Prints every `dt<digits>` occurrence with context, and every `*.cs.konami.net`
/ `gate_` string it can find outside the known five hosts.
"""
from __future__ import annotations

import re
import struct

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

PAT_DT = re.compile(rb"\bdt\d{3,4}\b")
PAT_HOST = re.compile(rb"[a-z0-9][a-z0-9\-]{2,40}\.(?:cs\.konami\.net|konami\.(?:net|com))")
PAT_GATE = re.compile(rb"[A-Za-z0-9_/\.]{0,40}gate_[A-Za-z0-9_\.]{1,60}")


def main() -> int:
    d = open(SO, "rb").read()
    print("=== dt<digits> tokens ===")
    seen = set()
    for m in PAT_DT.finditer(d):
        s = m.group().decode()
        if s in seen:
            continue
        seen.add(s)
        ctx = d[max(0, m.start() - 40):m.end() + 40]
        print("  %-10s @0x%X  %r" % (s, m.start(), ctx))

    print("\n=== konami hosts in the binary ===")
    seen = set()
    for m in PAT_HOST.finditer(d):
        s = m.group().decode()
        if s in seen:
            continue
        seen.add(s)
        print("  %-42s @0x%X" % (s, m.start()))

    print("\n=== gate_ path strings ===")
    seen = set()
    for m in PAT_GATE.finditer(d):
        s = m.group().decode("latin1")
        if s in seen or "gate_" not in s:
            continue
        seen.add(s)
        if len(seen) > 60:
            break
        print("  %-60s @0x%X" % (s, m.start()))

    # endpoint-config default table (0x7d65c84 loads defaults): dump the
    # strings it materialises by looking at literals referenced in that window
    print("\n=== literal strings near defaults 0x7d65c84 / cfg 0x7b101f8 ===")
    for va in (0x7d65c84, 0x7d6532c, 0x7b101f8):
        off = va - 0x4000
        blob = d[off:off + 0x400]
        strs = re.findall(rb"[\x20-\x7e]{6,}", blob)
        print("  %s: %s" % (hex(va), [s.decode() for s in strs[:12]]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
