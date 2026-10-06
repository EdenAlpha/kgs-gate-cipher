#!/usr/bin/env python3
"""Scan passthrough_capture.csv payloads for config-key-like ASCII strings."""
import os, re, sys, binascii

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "captures", "match-2026-09-26")
STATIONS = ["z1-tiamant-client", "z2-elijah-hotspot-owner"]

KEYWORDS = (b"timeout", b"watchdog", b"idle", b"commandlack", b"threshold",
            b"outofplay", b"abort", b"ms.", b"Timeout", b"Ms", b"MS_")

RE_PRINT = re.compile(rb"[\x20-\x7e]{6,}")


def scan(st):
    p = os.path.join(BASE, st, "passthrough_capture.csv")
    found = {}
    n_pkts = 0
    ports = {}
    with open(p, "r", errors="replace") as f:
        for line in f:
            if line.startswith("#") or line.startswith("ts_ms"):
                continue
            parts = line.rstrip("\n").split(",")
            if len(parts) < 9:
                continue
            n_pkts += 1
            proto = parts[2]
            dport = parts[6] if len(parts) > 6 else "?"
            sport = parts[4] if len(parts) > 4 else "?"
            ports[(proto, dport)] = ports.get((proto, dport), 0) + 1
            hx = parts[-1].strip()
            if len(hx) < 40 or len(hx) % 2:
                continue
            try:
                raw = binascii.unhexlify(hx.encode())
            except Exception:
                continue
            for m in RE_PRINT.finditer(raw):
                s = m.group(0)
                low = s.lower()
                for kw in (b"timeout", b"watchdog", b"idle", b"commandlack",
                           b"threshold", b"outofplay", b"abort", b"receive",
                           b"config", b"setting", b"watch dog"):
                    if kw in low:
                        found.setdefault(s, 0)
                        found[s] += 1
                        break
    print("== %s : %d packets ==" % (st, n_pkts))
    print("   top dst ports: %s"
          % sorted(ports.items(), key=lambda kv: -kv[1])[:8])
    if found:
        print("   keyword-bearing strings:")
        for s, c in sorted(found.items(), key=lambda kv: -kv[1])[:60]:
            print("      x%-4d %s" % (c, s.decode("ascii", "replace")))
    else:
        print("   NO config-like strings in any payload")
    print()


for s in STATIONS:
    scan(s)
