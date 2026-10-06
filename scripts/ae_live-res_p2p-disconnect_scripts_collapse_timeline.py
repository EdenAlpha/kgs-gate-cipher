#!/usr/bin/env python3
"""Per-second rate breakdown for the two anomalous exports.

scan_exports.py found that 1790283191028 and 1790283204171 -- the same match
captured from both ends -- carry 400 s at 27.3 pkt/s where every other export
sits near 54 pkt/s, and that in the final third one direction has 26 packets
against the other's 3626. That is a one-sided collapse, which is exactly the
shape of a P2P disconnect, and it is the only thing like it in the whole set.

This prints the rate timeline so the moment of collapse is a number, not an
impression.
"""
from __future__ import annotations

import collections
import csv
import glob
import os
import sys
import zipfile

WANT = ("1790283191028", "1790283204171")


def rows_of(path_zip):
    with zipfile.ZipFile(path_zip) as zf:
        n = [x for x in zf.namelist() if x.endswith("udp_trace.csv")][0]
        data = zf.read(n).decode("utf-8", "replace")
    rows, header = [], None
    for line in data.splitlines():
        if line.startswith("#"):
            body = line[1:].strip()
            if "," in body and "=" not in body:
                header = [c.strip() for c in body.split(",")]
            continue
        if header is None:
            header = [c.strip() for c in line.strip().split(",")]
            continue
        if line.strip():
            rows.append(line)
    return list(csv.DictReader(rows, fieldnames=header))


def main() -> int:
    pat = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
           r"\*\peerlink_match_*.zip")
    for z in sorted(glob.glob(pat)):
        name = os.path.basename(z)[len("peerlink_match_"):-len(".zip")]
        if name not in WANT:
            continue
        rows = rows_of(z)
        if not rows:
            continue
        per = collections.defaultdict(collections.Counter)
        flags = collections.defaultdict(collections.Counter)
        for r in rows:
            try:
                t = float(r["rel_ms"]) / 1000.0
            except Exception:
                continue
            s = int(t)
            per[s][r["dir"]] += 1
            for tok in (r.get("flags") or "").split("|"):
                if tok.strip():
                    flags[s][tok.strip()] += 1
        secs = sorted(per)
        print("=" * 74)
        print("export %s   %d packets, t=%.0f..%.0f s" % (name, len(rows), secs[0], secs[-1]))
        print("=" * 74)
        print("  %6s %7s %7s %7s   %s" % ("t_s", "total", "out", "in", "flags"))
        for s in secs:
            c = per[s]
            o, i = c.get("out", 0), c.get("in", 0)
            extra = ""
            if o == 0 and i > 0:
                extra = "<-- INBOUND ONLY"
            elif i == 0 and o > 0:
                extra = "<-- OUTBOUND ONLY"
            elif o and i and (o > 8 * i or i > 8 * o):
                extra = "<-- heavily one-sided (%d:1)" % (max(o, i) // max(1, min(o, i)))
            interesting = ",".join(
                sorted(k for k in flags[s] if k not in
                       ("tunnel", "stun", "stableKnown", "peerFab", "fromPeer", "inject")))
            if interesting:
                extra += "  extra:%s" % interesting
            if s % 4 == 0 or extra:
                print("  %6d %7d %7d %7d   %s" % (s, o + i, o, i, extra))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
