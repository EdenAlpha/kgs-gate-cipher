#!/usr/bin/env python3
"""Tight measurement of link silence at each of the 3 quit events, per phone.

Bridge gap events:  `BRIDGE-GAP-T0 gapMs=G` logged at time T when a packet
arrived after G ms of silence  =>  previous packet was at T-G.

At the quit (cliff) time C:
    last packet  = max T <= C          =>  idle_min = C - T
    prev packet  = T - gapMs           =>  idle_max = C - (T - gapMs)
so the true silence at the quit lies in [idle_min, idle_max].

Compare that window against the compiled thresholds
{0,10,30,60,90,120,180,300} ms.
"""
import re, os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "captures", "match-2026-09-26")
STATIONS = ["z1-tiamant-client", "z2-elijah-hotspot-owner"]

RE_TS = re.compile(r"\[(\d\d):(\d\d):(\d\d)\.(\d\d\d)\]")
RE_GAP = re.compile(r"BRIDGE-GAP-T0\] gapMs=(\d+)")
RE_CLIFF = re.compile(r"cliff confirmed")
RE_BURST = re.compile(r"54B burst \((\d+)\)")

THRESHOLDS = [0, 10, 30, 60, 90, 120, 180, 300]


def tms(m):
    return ((int(m[0]) * 60 + int(m[1])) * 60 + int(m[2])) * 1000 + int(m[3])


def fmt(ms):
    return "%02d:%02d:%02d.%03d" % (ms // 3600000, (ms // 60000) % 60,
                                    (ms // 1000) % 60, ms % 1000)


def run(st):
    p = os.path.join(BASE, st, "match_log.txt")
    gaps, cliffs, bursts = [], [], []
    with open(p, "r", errors="replace") as f:
        for line in f:
            t = RE_TS.search(line)
            if not t:
                continue
            ms = tms(t.group(1, 2, 3, 4))
            m = RE_GAP.search(line)
            if m:
                gaps.append((ms, int(m.group(1))))
                continue
            if RE_CLIFF.search(line):
                cliffs.append(ms)
                continue
            if RE_BURST.search(line):
                bursts.append(ms)
                continue

    print("=" * 80)
    print(st)
    print("=" * 80)
    for c in cliffs:
        prev_gap_ev = [(t, g) for t, g in gaps if t <= c]
        if not prev_gap_ev:
            continue
        t_last, g_last = max(prev_gap_ev, key=lambda x: x[0])
        t_prev = t_last - g_last
        idle_min = c - t_last           # last packet was this recently
        idle_max = c - t_prev           # ... or, at oldest, this long ago
        nb = [b for b in bursts if 0 <= (c - b) <= 3000]
        print("  QUIT cliff @%s" % fmt(c))
        print("     last bridge packet  @%s   (silence before it = %d ms)"
              % (fmt(t_last), g_last))
        print("     packet before that  @%s" % fmt(t_prev))
        print("     -> silence AT quit in [%d, %d] ms" % (idle_min, idle_max))
        if nb:
            b = nb[-1]
            print("     54B burst @%s  (%d ms before cliff); burst->cliff gap "
                  "%d ms" % (fmt(b), c - b, c - b))
        fits = [t for t in THRESHOLDS if idle_min <= t <= idle_max]
        poss = [t for t in THRESHOLDS if t <= idle_max]
        print("     thresholds INSIDE this window : %s" % fits)
        print("     thresholds not ruled out      : %s" % poss)
        print()
    print()


for s in STATIONS:
    run(s)
