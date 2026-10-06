#!/usr/bin/env python3
"""Scan every exported match and find the ones that actually show a disconnect.

One export (1790619339531) was analysed first and turned out to be perfectly
healthy for its whole 230 s: steady ~54 pkt/s, worst in-session gap 374 ms,
sub-millisecond latencies, and 100% of packets on the peerFab <-> fromPeer
tunnel. It was cut off by the export, not by the network -- so it cannot
explain a disconnect.

This scans all of them and scores each on the things that distinguish a real
disconnect from a clean stop:

  * a sustained collapse in packet rate (not a single quiet second)
  * a one-sided stall (traffic continues in one direction only)
  * a large late-session inter-arrival gap
  * any non-tunnel traffic appearing (a fallback path being used)

so the user can be told which export to look at, instead of guessing.
"""
from __future__ import annotations

import collections
import glob
import io
import os
import sys
import zipfile


def read_trace(data: str):
    rows, header, meta = [], None, {}
    for line in data.splitlines():
        if line.startswith("#"):
            body = line[1:].strip()
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
        if line.strip():
            rows.append(line)
    if not rows or not header:
        return [], None
    import csv
    return list(csv.DictReader(rows, fieldnames=header)), meta


def score(trace_bytes):
    rows, meta = read_trace(trace_bytes)
    if not rows:
        return None
    n = len(rows)

    def rel(r):
        try:
            return float(r["rel_ms"]) / 1000.0
        except Exception:
            return None

    times = sorted(t for t in (rel(r) for r in rows) if t is not None)
    if len(times) < 20:
        return None
    span = times[-1] - times[0]
    if span <= 0:
        return None

    # per-second counts
    hist = collections.Counter(int(t) for t in times)
    secs = sorted(hist)
    peak = max(hist.values())

    # longest run of seconds below 20% of peak, ignoring the final 2 seconds
    body = [s for s in secs if s < times[-1] - 2]
    run, best_run, run_at = 0, 0, None
    prev = None
    for s in body:
        if prev is not None and s == prev + 1 and hist[s] < max(3, 0.2 * peak):
            run += 1
        elif hist[s] < max(3, 0.2 * peak):
            run = 1
        else:
            run = 0
        if run > best_run:
            best_run, run_at = run, s - run + 1
        prev = s

    # largest late-session gap (after 20% of the session)
    late = [t for t in times if t > times[0] + 0.2 * span]
    late_gap = 0.0
    late_at = 0.0
    for a, b in zip(late, late[1:]):
        if b - a > late_gap:
            late_gap, late_at = b - a, a

    # direction balance in the last third
    third = times[0] + (2.0 / 3.0) * span
    tail = collections.Counter(r["dir"] for r in rows
                               if (rel(r) or -1) >= third)
    o, i = tail.get("out", 0), tail.get("in", 0)
    one_sided = (o == 0) != (i == 0)

    # did anything outside the tunnel path appear?
    fl = collections.Counter()
    for r in rows:
        for tok in (r.get("flags") or "").split("|"):
            tok = tok.strip()
            if tok:
                fl[tok] += 1
    tunnel = fl.get("tunnel", 0)
    non_tunnel = n - tunnel

    return {
        "packets": n, "span_s": span, "rate": n / span, "peak_pps": peak,
        "stall_run_s": best_run, "stall_at_s": run_at,
        "late_gap_s": late_gap, "late_gap_at_s": late_at,
        "tail_out": o, "tail_in": i, "one_sided": one_sided,
        "non_tunnel": non_tunnel,
        "verdict": ("DISCONNECT-LIKE" if (best_run >= 3 or one_sided
                                          or late_gap > 1.0)
                    else "clean"),
    }


def main() -> int:
    zips = sorted(glob.glob(sys.argv[1] if len(sys.argv) > 1 else
                            r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
                            r"\uploads\*\peerlink_match_*.zip"))
    print("scanning %d exports\n" % len(zips))
    print("%-22s %7s %7s %7s %8s %8s %-6s %-6s %s"
          % ("export", "pkt", "span_s", "pps", "stall_s", "lateGap", "out/in", "nontun", "verdict"))
    out = []
    for z in zips:
        name = os.path.basename(z)[len("peerlink_match_"):-len(".zip")]
        try:
            with zipfile.ZipFile(z) as zf:
                names = [n for n in zf.namelist() if n.endswith("udp_trace.csv")]
                if not names:
                    print("%-22s  (no udp_trace.csv)" % name)
                    continue
                data = zf.read(names[0]).decode("utf-8", "replace")
        except Exception as e:
            print("%-22s  ERROR %s" % (name, e))
            continue
        s = score(data)
        if not s:
            print("%-22s  (unusable trace)" % name)
            continue
        s["name"] = name
        out.append(s)
        print("%-22s %7d %7.1f %7.1f %5ds@%-4s %6.2fs %-6s %-6d %s"
              % (name, s["packets"], s["span_s"], s["rate"],
                 s["stall_run_s"], s["stall_at_s"], s["late_gap_s"],
                 "%d/%d" % (s["tail_out"], s["tail_in"]),
                 s["non_tunnel"], s["verdict"]))
    bad = [s for s in out if s["verdict"] != "clean"]
    print("\n%d of %d exports show a disconnect-like signature" % (len(bad), len(out)))
    for s in bad:
        print("  %s  stall=%ds@%s  lateGap=%.2fs@%.1fs  oneSided=%s  nonTunnel=%d"
              % (s["name"], s["stall_run_s"], s["stall_at_s"], s["late_gap_s"],
                 s["late_gap_at_s"], s["one_sided"], s["non_tunnel"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
