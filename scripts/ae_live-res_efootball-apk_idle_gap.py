#!/usr/bin/env python3
"""Measure the traffic-idle duration that preceded each game-initiated quit.

Reads match_log.txt (BRIDGE-GAP-T0 lines = inter-packet gaps on the bridge)
and correlates with the 0pps_cliff events in passthrough_capture.csv.

Gives, for each stall:
  - timestamp of the LAST bridge packet before the quit burst
  - timestamp of the 54B goodbye burst
  - idle_ms = quit - last_packet          (lower bound on the watchdog threshold)
and the MAX gap observed during normal play that did NOT end in a quit.
"""
import re, os, sys, datetime

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "captures", "match-2026-09-26")

STATIONS = ["z1-tiamant-client", "z2-elijah-hotspot-owner"]

RE_GAP = re.compile(r"\[(\d\d):(\d\d):(\d\d)\.(\d\d\d)\].*BRIDGE-GAP-T0\] gapMs=(\d+)")
RE_ANY = re.compile(r"\[(\d\d):(\d\d):(\d\d)\.(\d\d\d)\]")
RE_BURST = re.compile(r"\[(\d\d):(\d\d):(\d\d)\.(\d\d\d)\].*54B burst")
RE_CLIFF = re.compile(r"\[(\d\d):(\d\d):(\d\d)\.(\d\d\d)\].*cliff confirmed")


def to_ms(m):
    h, mi, s, ms = int(m[0]), int(m[1]), int(m[2]), int(m[3])
    return ((h * 60 + mi) * 60 + s) * 1000 + ms


def fmt(ms):
    return "%02d:%02d:%02d.%03d" % (ms // 3600000, (ms // 60000) % 60,
                                    (ms // 1000) % 60, ms % 1000)


def cliffs(st):
    """epoch-ms of 0pps_cliff events (from passthrough_capture.csv)."""
    p = os.path.join(BASE, st, "passthrough_capture.csv")
    out = []
    # session start epoch (from match_log first line) -> use known anchor
    with open(p, "r", errors="replace") as f:
        for line in f:
            if not line.startswith("# event"):
                if line.startswith("#") or line.startswith("ts_ms"):
                    continue
                break
            m = re.match(r"# event (\d+) (\S+)", line)
            if m and m.group(2) == "0pps_cliff":
                out.append(int(m.group(1)))
    return out


def analyze(st):
    p = os.path.join(BASE, st, "match_log.txt")
    gaps = []          # (time_ms, gap_ms)  -- gap ENDING at time_ms
    bursts = []
    clifflogs = []
    with open(p, "r", errors="replace") as f:
        for line in f:
            m = RE_GAP.search(line)
            if m:
                gaps.append((to_ms(m.group(1, 2, 3, 4)), int(m.group(5))))
                continue
            m = RE_BURST.search(line)
            if m:
                bursts.append(to_ms(m.group(1, 2, 3, 4)))
                continue
            m = RE_CLIFF.search(line)
            if m:
                clifflogs.append(to_ms(m.group(1, 2, 3, 4)))
    return gaps, bursts, clifflogs


def main():
    for st in STATIONS:
        print("=" * 78)
        print(st)
        print("=" * 78)
        gaps, bursts, clifflogs = analyze(st)
        print("  bridge-gap lines: %d   54B bursts: %d   cliff logs: %d"
              % (len(gaps), len(bursts), len(clifflogs)))

        # reconstruct packet times: gap event logged ON ARRIVAL of a packet
        pkts = [(t, 0) for t, g in gaps]   # arrival times known
        # the "last packet before burst" = last gap-arrival <= burst
        for b in sorted(set(bursts)):
            prev = [t for t, g in gaps if t <= b]
            last = max(prev) if prev else None
            # the gap that ENDED at last tells how long the silence was
            gend = [(t, g) for t, g in gaps if t == last]
            gprev = gend[0][1] if gend else None
            # find the arrival before `last` to get true silence window
            if last is not None:
                before = [t for t, g in gaps if t < last]
                start = max(before) if before else None
                silence = (last - start) if (start is not None) else None
            else:
                silence = None
            # gap immediately preceding the burst (arrival->burst)
            lead = (b - last) if last is not None else None
            print("  burst @%s  last_bridge_pkt @%s (gapEnded=%sms) "
                  "silence_before=%sms  pkt->burst=%sms  total_idle=%sms"
                  % (fmt(b), fmt(last) if last else "-",
                     gprev, silence, lead,
                     (silence + lead) if (silence is not None and lead is not None) else None))

        # gaps that did NOT lead to a burst within 5 s
        notrig = [g for t, g in gaps
                  if not any(0 <= (b - t) <= 5000 for b in bursts)]
        notrig.sort()
        if notrig:
            print("  gaps NOT followed by a quit burst within 5s: n=%d  max=%d  "
                  "p99=%d  p95=%d"
                  % (len(notrig), notrig[-1],
                     notrig[int(len(notrig) * 0.99)],
                     notrig[int(len(notrig) * 0.95)]))
        allg = sorted(g for _, g in gaps)
        print("  all gaps: n=%d max=%d p99=%d p95=%d median=%d"
              % (len(allg), allg[-1], allg[int(len(allg) * 0.99)],
                 allg[int(len(allg) * 0.95)], allg[len(allg) // 2]))
        print()


if __name__ == "__main__":
    main()
