#!/usr/bin/env python3
"""Frame-level timeline of the phone's gRPC flow to pes22-game.
Is it a live session (periodic traffic both ways) or a single rejected response?"""
from __future__ import annotations

import socket
import sys

import dpkt

PCAP = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
        r"\168ed698-75b8-4a9d-8e53-a7c6570a633e"
        r"\PCAPdroid_29_Sep_10_31_15.pcap")
WANT = ("10.215.173.1", 32912)


def main() -> int:
    pkts = []
    with open(PCAP, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.sport == WANT[1] or tcp.dport == WANT[1]:
                pkts.append((ts, ip.src, tcp.sport, ip.dst, tcp.dport,
                             tcp.flags, tcp.data))
    if not pkts:
        print("flow not found")
        return 1
    pkts.sort(key=lambda p: p[0])
    t0 = pkts[0][0]
    print("packets in flow:", len(pkts))
    app = [(ts, src, sport, dst, dport, d) for ts, src, sport, dst, dport, fl, d in pkts if d]
    print("with payload:", len(app))
    for ts, src, sport, dst, dport, d in app:
        direction = "->" if sport == WANT[1] else "<-"
        kind = ("CH" if d[:1] == b"\x16" and d[5:6] == b"\x01"
                else "HS" if d[:1] == b"\x16"
                else "APP" if d[:1] == b"\x17"
                else "CS" if d[:1] == b"\x14"
                else "ALERT" if d[:1] == b"\x15"
                else "raw")
        print("  +%7.2fs %s %-4s len=%-5d %s" % (
            ts - t0, direction, kind, len(d), d[:16].hex()))
    # byte totals per 10s bucket
    print("\n== per-10s buckets (c=phone, s=server) ==")
    buckets = {}
    for ts, src, sport, dst, dport, d in app:
        b = int((ts - t0) // 10) * 10
        k = buckets.setdefault(b, [0, 0])
        if sport == WANT[1]:
            k[0] += len(d)
        else:
            k[1] += len(d)
    for b in sorted(buckets):
        c, s = buckets[b]
        print("  t=%4ds  phone->srv %6d   srv->phone %6d" % (b, c, s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
