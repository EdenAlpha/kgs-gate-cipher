#!/usr/bin/env python3
"""Analyse a PeerLink passthrough_capture.csv.

Checks three things:
  1. does the internet-side capture contain the game's Konami connections?
  2. do the 34-byte "IeFootball(TM)" blobs appear on the wire?
  3. event markers / hosts present.
"""
from __future__ import annotations

import csv
import re
import sys
from collections import Counter, defaultdict

PATH = sys.argv[1] if len(sys.argv) > 1 else (
    r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\match_new2"
    r"\passthrough_capture.csv")

BLOB = b"\x00\x00\x01\x07"


def main() -> int:
    rows = []
    events = []
    with open(PATH, encoding="utf-8", errors="replace") as f:
        for r in csv.reader(f):
            if not r:
                continue
            if r[0].startswith("#"):
                if "event" in r[0].lower():
                    events.append(r[0])
                continue
            if r[0] == "ts_ms":
                continue
            if len(r) < 9:
                continue
            try:
                rows.append((int(r[0]), r[1], r[2], r[3], int(r[4]), r[5],
                             int(r[6]), int(r[7]), r[8]))
            except ValueError:
                continue

    print("packets: %d   event markers: %d" % (len(rows), len(events)))
    if events:
        seen = set()
        print("--- event markers (first 25 distinct) ---")
        for e in events:
            k = e[:110]
            if k in seen:
                continue
            seen.add(k)
            print("  ", k)
            if len(seen) >= 25:
                break

    proto = Counter(r[2] for r in rows)
    print("--- protocols ---", dict(proto))

    dports = Counter(r[6] for r in rows)
    print("--- top dports ---", dports.most_common(12))

    hosts = Counter(r[5] for r in rows)
    print("--- top destinations ---")
    for h, c in hosts.most_common(15):
        print("   %-18s %d" % (h, c))

    # 34-byte blob check on the wire
    blobs = 0
    blob_hosts = Counter()
    total_tcp = 0
    for r in rows:
        if r[2] != "tcp":
            continue
        total_tcp += 1
        try:
            pay = bytes.fromhex(r[8])
        except ValueError:
            continue
        # skip the 20-byte IP header, then 20-byte TCP header
        body = pay[40:]
        if body.startswith(BLOB) and len(body) == 34:
            blobs += 1
            blob_hosts[(r[3], r[5])] += 1
    print("--- 34-byte blobs on the wire: %d of %d TCP packets ---"
          % (blobs, total_tcp))
    for k, c in blob_hosts.most_common(10):
        print("   %s -> %s : %d" % (k[0], k[1], c))

    # any Konami-looking TLS? (SNI is plaintext in TLS ClientHello)
    sni = Counter()
    konami = 0
    for r in rows:
        try:
            pay = bytes.fromhex(r[8])
        except ValueError:
            continue
        for m in re.finditer(rb"[a-z0-9.-]+\.konami\.net", pay):
            konami += 1
            sni[m.group(0).decode()] += 1
    print("--- konami hostnames visible in plaintext: %d ---" % konami)
    for k, c in sni.most_common(20):
        print("   %-40s %d" % (k, c))

    # how many 443 flows, and total bytes per flow
    flows = defaultdict(lambda: [0, 0])
    for r in rows:
        key = (r[5], r[6])
        flows[key][0] += 1
        flows[key][1] += r[7]
    print("--- biggest flows (dst, dport) ---")
    for k, v in sorted(flows.items(), key=lambda x: -x[1][1])[:12]:
        print("   %-18s %-6s pkts=%-5d bytes=%d" % (k[0], k[1], v[0], v[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
