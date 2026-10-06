"""stall_audit.py -- re-derive, from the raw captures, (a) how long the recording
is, (b) how many stalls there are, and (c) whether the phones' own network links
were alive during those stalls.

  stall_audit.py

Everything here is computed from passthrough_capture.csv event markers and the
ts_ms column; nothing is taken from the written census.
"""
import collections
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "captures", "match-2026-09-26")
PHONES = ["z1-tiamant-client", "z2-elijah-hotspot-owner"]


def load(ph):
    path = os.path.join(BASE, ph, "passthrough_capture.csv")
    rows, events = [], []
    hdr = None
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("# event"):
            parts = line.split()
            if len(parts) > 3 and parts[2].isdigit():
                events.append((int(parts[2]), parts[3]))
            continue
        if hdr is None:
            if line.startswith("ts_ms,"):
                hdr = line.split(",")
            continue
        if not line:
            continue
        c = line.split(",")
        try:
            ts = int(c[0])
        except ValueError:
            continue
        rows.append((ts, c[1], c[2], c[3], c[5], int(c[7])))
    return rows, events


data = {}
for ph in PHONES:
    rows, events = load(ph)
    data[ph] = (rows, events)

    ts = [r[0] for r in rows]
    span = (max(ts) - min(ts)) / 60000.0
    print("=" * 78)
    print(ph)
    print("=" * 78)
    print("  packets          : %d" % len(rows))
    print("  first ts_ms      : %d" % min(ts))
    print("  last  ts_ms      : %d" % max(ts))
    print("  RECORDING LENGTH : %.2f min" % span)
    print("  events           : %d" % len(events))

    cliffs = [t for t, n in events if n == "0pps_cliff"]
    print("  0pps_cliff events: %d" % len(cliffs))
    if cliffs:
        base = min(ts)
        for i, t in enumerate(cliffs, 1):
            print("     #%d  +%7.1f s" % (i, (t - base) / 1000.0))
        if len(cliffs) % 2 == 0:
            print("  -> %d PAIRS" % (len(cliffs) // 2))
            for i in range(0, len(cliffs), 2):
                a, b = cliffs[i], cliffs[i + 1]
                print("     pair %d: %.1f s apart" % (i // 2 + 1, (b - a) / 1000.0))
    print()

# ---------------------------------------------------------------- stall windows
print("=" * 78)
print("STALL WINDOWS (cliff pairs) and what was still flowing on each phone")
print("=" * 78)

z1r, z1e = data["z1-tiamant-client"]
z2r, z2e = data["z2-elijah-hotspot-owner"]
z1c = [t for t, n in z1e if n == "0pps_cliff"]


def window(rows, a, b, pad=0):
    return [r for r in rows if a - pad <= r[0] <= b + pad]


for i in range(0, len(z1c), 2):
    a, b = z1c[i], z1c[i + 1]
    print("-" * 78)
    print("stall %d : window %.1f s" % (i // 2 + 1, (b - a) / 1000.0))
    for ph, rows in (("z1", z1r), ("z2", z2r)):
        inw = window(rows, a, b)
        prot = collections.Counter(r[2] for r in inw)
        dports = collections.Counter(r[4] for r in inw)
        # non-game traffic = anything that is not the peer game port
        top = ", ".join("%s=%d" % (d, c) for d, c in dports.most_common(5))
        print("  %s  packets in window: %4d   proto: %s" %
              (ph, len(inw), dict(prot)))
        print("        top dst: %s" % top)
    print()
