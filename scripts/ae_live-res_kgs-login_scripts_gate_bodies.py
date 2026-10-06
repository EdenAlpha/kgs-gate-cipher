#!/usr/bin/env python3
"""Dump the plaintext port-80 bodies from the capture, in order.

The ordered flow sequence shows the game contacting `44.232.213.50:443`
(its gRPC endpoint) at t=43 s and t=56 s, and only afterwards calling
`POST /ntl/api/GateInfo.php` on `ntl.service.konami.net` at t=93 s. So the gRPC
channel is the bootstrap and the NTL gate is not what hands it out.

The gate call is the only game traffic in this capture that is not encrypted, so
its request and response bodies are the one place the login's parameters can be
read directly. This prints them in full.
"""
from __future__ import annotations

import binascii
import os
import struct
import sys

CSV = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\pt\passthrough_capture.csv"


def tcp_of(ip):
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    p = ihl
    if len(ip) < p + 20:
        return None
    sport, dport = struct.unpack(">HH", ip[p:p + 4])
    doff = (ip[p + 12] >> 4) * 4
    if doff < 20:
        return None
    return sport, dport, ip[p + doff:]


def main() -> int:
    t0 = None
    shown = 0
    for line in open(CSV, encoding="utf-8", errors="replace"):
        if line.startswith("#"):
            continue
        p = line.rstrip("\n").split(",")
        if len(p) < 9:
            continue
        try:
            ts = int(p[0])
            ip = binascii.unhexlify(p[8].strip())
        except Exception:
            continue
        if t0 is None:
            t0 = ts
        t = tcp_of(ip)
        if not t:
            continue
        sport, dport, pay = t
        if not pay or (dport != 80 and sport != 80):
            continue
        txt = pay.decode("latin1", "replace")
        if not (txt.startswith(("GET ", "POST ", "PUT ", "HTTP/1."))):
            continue
        shown += 1
        print("=" * 78)
        print("t=%.2fs  %s  %s:%d -> %s:%d  (%d bytes)"
              % ((ts - t0) / 1000.0, p[1].upper(), p[3], sport, p[5], dport,
                 len(pay)))
        print("=" * 78)
        parts = txt.split("\r\n\r\n", 1)
        print(parts[0][:1400])
        if len(parts) > 1:
            body = parts[1]
            print("\n--- body (%d bytes) ---" % len(body))
            print(body[:3000])
        print()
    print("total port-80 messages with a readable start line: %d" % shown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
