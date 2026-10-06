#!/usr/bin/env python3
"""Pull every plaintext HTTP request/response out of the passthrough capture.

Port 80 traffic is unencrypted, so the bodies are the game's own words: real
titleCode/version, real ReportLog diagnostics, possibly the real user_id /
session_id / device hash.  Those values are what our emulated request is
missing (they serialise as `NotImplement` because we never ran the init that
fills them).
"""
from __future__ import annotations

import csv
import os
import socket
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "pcap_new", "passthrough_capture.csv")


def tcp_parts(raw: bytes):
    if len(raw) < 20 or (raw[0] >> 4) != 4:
        return None
    ihl = (raw[0] & 0xF) * 4
    if raw[9] != 6 or len(raw) < ihl + 20:
        return None
    th = raw[ihl:]
    sport, dport = struct.unpack(">HH", th[0:4])
    off = ((th[12] >> 4) & 0xF) * 4
    return (socket.inet_ntoa(raw[12:16]), sport,
            socket.inet_ntoa(raw[16:20]), dport, th[off:])


def main() -> int:
    streams = {}
    order = []
    with open(CSV_PATH, "r", errors="replace") as f:
        rows = (l for l in f if not l.startswith("#"))
        for r in csv.reader(rows):
            if len(r) < 9 or not r[0].isdigit():
                continue
            ts, direction = int(r[0]), r[1]
            p = tcp_parts(bytes.fromhex(r[8]))
            if not p:
                continue
            src, sport, dst, dport, payload = p
            key = (src, sport, dst, dport)
            if key not in streams:
                streams[key] = {"dir": direction, "ts": ts, "up": b"",
                                "down": b""}
                order.append(key)
            streams[key]["up" if direction == "t" else "down"] += payload

    for key in order:
        st = streams[key]
        up, down = st["up"], st["down"]
        if not (up[:4] in (b"GET ", b"POST", b"PUT ") or
                down[:5] == b"HTTP/"):
            continue
        print("=" * 78)
        print("%dms  %s:%d -> %s:%d  (up=%dB down=%dB)"
              % (st["ts"], key[0], key[1], key[2], key[3],
                 len(up), len(down)))
        print("- request -")
        print(up.decode("latin1", "replace")[:2400])
        print("- response -")
        print(down.decode("latin1", "replace")[:1200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
