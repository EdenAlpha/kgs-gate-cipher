#!/usr/bin/env python3
"""In-match inbound-game idleness vs the three quit events.

Sources (both ms-resolution, full session):
  [NATIVE/LAT] inboundQueue n=<pkts> peakGame=<g>   ~every 5.1 s, INBOUND only
  [NATIVE/LAT] rxWake wakes=<w> packets=<p>          ~every 5.1 s, INBOUND only
  [?? BRIDGE-GAP-T0] gapMs=<g>                       inter-packet gap on the bridge
  # event <epoch> 0pps_cliff                         from passthrough_capture.csv

Match epoch 0: 02:30:06.440 -> 02:56:25.478 (final 0-0)
"""
import re, os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "captures", "match-2026-09-26")
STATIONS = ["z1-tiamant-client", "z2-elijah-hotspot-owner"]

RE_TS = re.compile(r"\[(\d\d):(\d\d):(\d\d)\.(\d\d\d)\]")
RE_IQ = re.compile(r"inboundQueue maxMs=(\d+) avgUs=(\d+) n=(\d+) peakGame=(\d+) peakControl=(\d+)")
RE_RW = re.compile(r"rxWake wakes=(\d+) packets=(\d+)")
RE_GAP = re.compile(r"BRIDGE-GAP-T0\] gapMs=(\d+)")
RE_BURST = re.compile(r"54B burst \((\d+)\)")
RE_CLIFF = re.compile(r"cliff confirmed")
RE_EPOCH = re.compile(r"Match epoch (\d+) started at (\d+)")
RE_FINAL = re.compile(r"SCREEN FINAL")

M_START = 2 * 3600000 + 30 * 60000 + 6000      # 02:30:06
M_END = 2 * 3600000 + 56 * 60000 + 25000        # 02:56:25


def tms(m):
    return ((int(m[0]) * 60 + int(m[1])) * 60 + int(m[2])) * 1000 + int(m[3])


def fmt(ms):
    return "%02d:%02d:%02d.%03d" % (ms // 3600000, (ms // 60000) % 60,
                                    (ms // 1000) % 60, ms % 1000)


def run(st):
    p = os.path.join(BASE, st, "match_log.txt")
    iq, rw, gaps, bursts, cliffs = [], [], [], [], []
    with open(p, "r", errors="replace") as f:
        for line in f:
            t = RE_TS.search(line)
            if not t:
                continue
            ms = tms(t.group(1, 2, 3, 4))
            m = RE_IQ.search(line)
            if m:
                iq.append((ms, int(m.group(3)), int(m.group(4)), int(m.group(5))))
                continue
            m = RE_RW.search(line)
            if m:
                rw.append((ms, int(m.group(1)), int(m.group(2))))
                continue
            m = RE_GAP.search(line)
            if m:
                gaps.append((ms, int(m.group(1))))
                continue
            if RE_BURST.search(line):
                bursts.append(ms)
                continue
            if RE_CLIFF.search(line):
                cliffs.append(ms)
                continue
    # cliffs come from the passthrough events too (epoch); use log ones
    print("=" * 78)
    print(st)
    print("=" * 78)

    # --- inbound game packets: consecutive zero-peakGame runs inside the match
    inm = [x for x in iq if M_START <= x[0] <= M_END]
    print("  inboundQueue samples in match: %d" % len(inm))
    runs = []
    cur = None
    for t, n, pg, pc in inm:
        if pg == 0:
            if cur is None:
                cur = [t, t, 0]
            cur[1] = t
            cur[2] += n
        else:
            if cur is not None:
                runs.append(tuple(cur))
                cur = None
    if cur:
        runs.append(tuple(cur))
    runs = [r for r in runs if (r[1] - r[0]) >= 5000]   # spans >= one full interval
    runs.sort(key=lambda r: -(r[1] - r[0]))
    print("  longest stretches with ZERO inbound GAME packets:")
    for a, b, n in runs[:6]:
        print("     %s -> %s   span=%6d ms   (ctrl pkts still arriving: %d)"
              % (fmt(a), fmt(b), b - a, n))

    # --- max in-match bridge gap NOT followed by a quit
    burst_set = sorted(set(bursts))
    nogap = [g for t, g in gaps
             if M_START <= t <= M_END
             and not any(0 <= (b - t) <= 5000 for b in burst_set)]
    nogap.sort()
    print("  in-match bridge gaps with no burst in next 5s: n=%d max=%d p99=%d "
          "p95=%d median=%d"
          % (len(nogap), nogap[-1], nogap[int(len(nogap) * .99)],
             nogap[int(len(nogap) * .95)], nogap[len(nogap) // 2]))

    # --- around each quit
    for c in cliffs:
        print("  ---- quit cliff @%s ----" % fmt(c))
        for t, n, pg, pc in iq:
            if c - 22000 <= t <= c + 12000:
                print("       inbound @%s n=%-4d peakGame=%d peakControl=%d  "
                      "dt cliff=%+d ms" % (fmt(t), n, pg, pc, t - c))
        prev = [(t, g) for t, g in gaps if t <= c]
        if prev:
            t, g = max(prev)
            print("       last bridge pkt @%s gapEnded=%dms  dt cliff=%+d ms"
                  % (fmt(t), g, t - c))
        bs = [b for b in burst_set if abs(b - c) <= 60000]
        if bs:
            print("       nearest 54B bursts: %s"
                  % ", ".join("%s(%+dms)" % (fmt(b), b - c) for b in bs))
    print()


for s in STATIONS:
    run(s)
