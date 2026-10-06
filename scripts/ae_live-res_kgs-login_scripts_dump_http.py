#!/usr/bin/env python3
"""Print the plaintext HTTP conversation with Konami (port 80) around each stall."""
from __future__ import annotations

import sys
from collections import defaultdict

from stall_focus import load, ROOT, STALLS, T0, wall  # type: ignore


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "z1-tiamant-client"
    recs = load(f"{ROOT}\\{which}\\passthrough_capture.csv")

    print(f"=== {which}: packet counts by (proto, dir) ===")
    c = defaultdict(int)
    for r in recs:
        c[(r["proto"], r["dir"])] += 1
    for k, v in sorted(c.items()):
        print(f"   proto {k[0]:<4} dir {k[1]} : {v}")

    ip2name = {}
    for r in recs:
        if r["kind"] == "dns" and r["ans"]:
            for rt, val in r["ans"]:
                if rt == 1:
                    ip2name[val] = r["name"]

    http = [r for r in recs if r["proto"] == 6 and
            (r["sport"] == 80 or r["dport"] == 80)]
    hosts = sorted({(r["dst"] if r["dport"] == 80 else r["src"]) for r in http})
    print("\n=== port-80 hosts ===")
    for h in hosts:
        n = sum(1 for r in http if (r["dst"] if r["dport"] == 80 else r["src"]) == h)
        print(f"   {h:<20} {ip2name.get(h,'?'):<32} packets={n}")

    print("\n=== payloads carrying data (PSH or with body) ===")
    for r in http:
        body = r["_payload"]
        if not body:
            continue
        print(f"\n----- {wall(r['ts'])} dir={r['dir']} "
              f"{r['src']}:{r['sport']} -> {r['dst']}:{r['dport']} "
              f"flags={r['flags']} len={len(body)} -----")
        txt = body.decode("utf-8", "replace")
        if txt.isprintable() or "\r" in txt or "\n" in txt:
            print(txt)
        else:
            print(repr(body[:400]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
