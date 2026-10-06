#!/usr/bin/env python3
"""TLS record-level dump of every pes22-game flow in the capture.

We cannot read the bytes (TLS), but the record sizes + order ARE visible and
they answer the key question: what does a WORKING request/response pair look
like?  A request that got `500` would show a tiny response (the empty-body 500
is ~120B of HTTP framing + TLS overhead) and the app would stop.

Prints: ms, direction, TLS record type, length.
"""
from __future__ import annotations

import csv
import os
import socket
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "pcap_new", "passthrough_capture.csv")

T = {0x14: "CCS", 0x15: "ALERT", 0x16: "HANDSHAKE", 0x17: "APP"}


def tcp_parts(raw):
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


def recs(buf):
    i = 0
    while i + 5 <= len(buf):
        typ, ver = buf[i], buf[i + 1]
        if typ not in T or ver != 0x03:
            break
        ln = struct.unpack(">H", buf[i + 3:i + 5])[0]
        yield typ, ln
        i += 5 + ln


def main() -> int:
    flows = {}
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
            # a returning packet has the endpoints swapped: normalise the key
            if dport == 443:
                key = (src, sport, dst, dport, 443)
                who = "C->S"
            elif sport == 443:
                key = (dst, dport, src, sport, 443)
                who = "S->C"
            else:
                continue
            if key not in flows:
                flows[key] = []
                order.append(key)
            if payload:
                flows[key].append((ts, who, payload))

    t0 = None
    for key in order:
        evs = flows[key]
        t0 = t0 if t0 is not None else evs[0][0]
        print("\n=== %s:%d -> %s:%d  (%d segments)"
              % (key[0], key[1], key[2], key[3], len(evs)))
        for ts, who, payload in evs:
            for typ, ln in recs(payload):
                print("   %6dms %s  %-9s %5dB"
                      % (ts - t0, who, T[typ], ln))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
