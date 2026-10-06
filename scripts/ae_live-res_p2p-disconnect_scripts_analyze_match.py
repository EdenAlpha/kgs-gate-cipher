#!/usr/bin/env python3
"""Characterise a PeerLink match export's P2P session.

Answers, from the exported trace only:
  * how long the session ran and whether it ended or was cut off mid-stream
  * packet rate over time, per direction
  * the largest inter-arrival gaps (a P2P disconnect usually shows as a
    one-sided stall, not a symmetric loss)
  * whether the two directions stay balanced
  * the transport timing columns the tool itself records (kernel->user,
    user->sched, etc.) at their worst

This is descriptive, not a guess at a cause: every number is computed from the
CSV that the tool exported.
"""
from __future__ import annotations

import collections
import csv
import os
import sys

TRACE = "udp_trace.csv"


def load(path):
    rows = []
    meta = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        header = None
        for line in f:
            if line.startswith("#"):
                body = line[1:].strip()
                # the column header is itself comment-prefixed; it is the only
                # comment line with commas and no "key=value" tokens
                if "," in body and "=" not in body:
                    header = [c.strip() for c in body.split(",")]
                    continue
                for tok in body.split():
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        meta[k] = v
                continue
            if header is None:
                header = [c.strip() for c in line.strip().split(",")]
                continue
            rows.append(line)
    if not rows or header is None:
        return [], header or [], meta
    return list(csv.DictReader(rows, fieldnames=header)), header, meta


def main() -> int:
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    p = os.path.join(d, TRACE)
    if not os.path.exists(p):
        print("no %s in %s" % (TRACE, d))
        return 1
    rows, hdr, meta = load(p)
    if not rows:
        print("no data rows")
        return 1

    print("=== trace metadata ===")
    for k, v in meta.items():
        print("  %-24s %s" % (k, v))

    n = len(rows)
    dirs = collections.Counter(r["dir"] for r in rows)
    print("\n=== volume ===")
    print("  rows            %d" % n)
    for k, v in dirs.most_common():
        print("  dir=%-3s          %6d  (%.1f%%)" % (k, v, 100.0 * v / n))

    def rel(r):
        """rel_ms is MILLISECONDS (despite the float formatting)."""
        try:
            return float(r["rel_ms"]) / 1000.0
        except Exception:
            return None

    times = [t for t in (rel(r) for r in rows) if t is not None]
    if not times:
        print("no usable rel_ms")
        return 1
    times.sort()
    span = times[-1] - times[0]
    print("\n=== timing ===")
    print("  first rel_s      %.3f" % times[0])
    print("  last  rel_s      %.3f" % times[-1])
    print("  span             %.1f s" % span)
    print("  overall rate     %.1f pkt/s" % (n / span if span else 0))

    # per-second histogram, to see rate decay or a hard stop
    hist = collections.Counter(int(t) for t in times)
    secs = sorted(hist)
    print("\n=== per-second rate (every 5s, and any second under 5 pkt/s) ===")
    zero = [s for s in secs if hist[s] < 5]
    if zero:
        # collapse runs
        runs, start, prev = [], zero[0], zero[0]
        for s in zero[1:]:
            if s != prev + 1:
                runs.append((start, prev))
                start = s
            prev = s
        runs.append((start, prev))
        print("  LOW-RATE seconds (%d):" % len(zero))
        for a, b in runs[:12]:
            print("    t=%4d..%4d s  (%d s)" % (a, b, b - a + 1))
    for s in secs[::5]:
        print("    t=%4d s  %4d pkt/s" % (s, hist[s]))

    # direction balance over time
    print("\n=== direction balance per 5 s (out/in) ===")
    bysec = collections.defaultdict(collections.Counter)
    for r in rows:
        t = rel(r)
        if t is None:
            continue
        bysec[t // 1000][r["dir"]] += 1
    for s in sorted(bysec)[::10]:
        c = bysec[s]
        o, i = c.get("out", 0), c.get("in", 0)
        print("    t=%4d s  out=%4d in=%4d  %s"
              % (s, o, i, "<-- ONE-SIDED" if (o == 0) != (i == 0) else ""))

    # largest gaps, per direction
    print("\n=== largest inter-arrival gaps ===")
    for dname in sorted(set(dirs)):
        ts = sorted(t for t in (rel(r) for r in rows if r["dir"] == dname)
                    if t is not None)
        gaps = [(ts[k + 1] - ts[k], ts[k]) for k in range(len(ts) - 1)]
        gaps.sort(reverse=True)
        print("  dir=%s  n=%d  top gaps (ms @ t_s):" % (dname, len(ts)))
        for g, at in gaps[:6]:
            print("     %6.0f ms  at t=%.1f s" % (g * 1000.0, at))

    # the tool's own timing columns
    print("\n=== worst recorded latencies (ms) ===")
    for col in ("rx_kernel_to_user_us", "tx_user_to_sched_us", "tx_sched_to_soft_us",
                "rx_enqueue_to_write_us", "rx_user_to_enqueue_us",
                "sender_delta_us", "rx_kernel_delta_us"):
        if col not in rows[0]:
            continue
        vals = []
        for r in rows:
            try:
                vals.append(int(r[col]))
            except Exception:
                pass
        if not vals:
            continue
        vals.sort()
        print("  %-24s n=%6d  p50=%6.1f  p99=%7.1f  max=%8.1f"
              % (col, len(vals), vals[len(vals) // 2] / 1000.0,
                 vals[int(len(vals) * 0.99)] / 1000.0, vals[-1] / 1000.0))

    print("\n=== packet classification (flags column) ===")
    fl = collections.Counter()
    for r in rows:
        for tok in (r.get("flags") or "").split("|"):
            tok = tok.strip()
            if tok:
                fl[tok] += 1
    for k, v in fl.most_common(24):
        print("  %-18s %6d  (%.1f%%)" % (k, v, 100.0 * v / n))

    print("\n=== status column ===")
    st = collections.Counter((r.get("status") or "").strip() for r in rows)
    for k, v in st.most_common(12):
        print("  %-24s %6d" % (k or "(blank)", v))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
