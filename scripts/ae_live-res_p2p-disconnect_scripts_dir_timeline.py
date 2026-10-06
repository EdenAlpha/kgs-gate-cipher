#!/usr/bin/env python3
"""Condensed outbound/inbound timeline for the two anomalous exports.

Finding so far: in these two (the same match, captured from both ends) traffic
is one-directional for the WHOLE session -- roughly 27 packets/s inbound and
almost nothing outbound -- whereas every healthy export runs near 54 pkt/s
split evenly. This prints the timeline so the question "did outbound ever
recover?" is answered with numbers.
"""
from __future__ import annotations

import collections
import csv
import glob
import os
import sys
import zipfile

WANT = ("1790283191028", "1790283204171")
PAT = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
       r"\*\peerlink_match_*.zip")


def rows_of(z):
    with zipfile.ZipFile(z) as zf:
        n = [x for x in zf.namelist() if x.endswith("udp_trace.csv")][0]
        data = zf.read(n).decode("utf-8", "replace")
    rows, hdr = [], None
    for line in data.splitlines():
        if line.startswith("#"):
            b = line[1:].strip()
            if "," in b and "=" not in b:
                hdr = [c.strip() for c in b.split(",")]
            continue
        if hdr is None:
            hdr = [c.strip() for c in line.strip().split(",")]
            continue
        if line.strip():
            rows.append(line)
    return list(csv.DictReader(rows, fieldnames=hdr))


def main() -> int:
    found = False
    for z in sorted(glob.glob(PAT)):
        name = os.path.basename(z)
        name = name[len("peerlink_match_"):-len(".zip")]
        if name not in WANT:
            continue
        found = True
        rows = rows_of(z)
        per = collections.defaultdict(collections.Counter)
        for r in rows:
            try:
                t = float(r["rel_ms"]) / 1000.0
            except Exception:
                continue
            per[int(t)][r["dir"]] += 1
        o = sum(per[s]["out"] for s in per)
        i = sum(per[s]["in"] for s in per)
        print("=" * 60)
        print("export %s   out=%d  in=%d   ratio in:out = %.1f:1"
              % (name, o, i, (i / o) if o else 9999))
        print("  %6s %6s %6s" % ("t_s", "out", "in"))
        for s in sorted(per):
            if s % 20 == 0 or per[s]["out"] > 3:
                mark = "   <-- outbound burst" if per[s]["out"] > 3 else ""
                print("  %6d %6d %6d%s" % (s, per[s]["out"], per[s]["in"], mark))
        print()
    if not found:
        print("neither export found under %s" % PAT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
