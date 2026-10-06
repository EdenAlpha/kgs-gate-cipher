#!/usr/bin/env python3
"""Extract the app's REAL gRPC session TLS handshake from the capture.

The session 10.0.0.2:53370 -> 44.232.213.50:443 is the command stream.  We
want exactly what the app offered AND what the server selected:
  * ALPN offered vs selected (grpc-exp? h2?)
  * TLS version, ciphers
  * record sizes + timing of the app-data exchange (framing fingerprint)
"""
from __future__ import annotations

import csv
import os
import socket
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "pcap_new", "passthrough_capture.csv")

TARGET = ("10.0.0.2", 53370, "44.232.213.50", 443)


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


def parse_hs(msgs: bytes):
    """Walk TLS handshake messages, return dict of ClientHello/ServerHello facts."""
    out = {}
    i = 0
    while i + 4 <= len(msgs):
        htype = msgs[i]
        ln = int.from_bytes(msgs[i + 1:i + 4], "big")
        body = msgs[i + 4:i + 4 + ln]
        i += 4 + ln
        if htype == 1 and len(body) >= 38:          # ClientHello
            p = 34
            sid = body[p]
            p += 1 + sid
            cs_len = struct.unpack(">H", body[p:p + 2])[0]
            p += 2
            out["ciphers_client"] = [body[j:j + 2].hex()
                                     for j in range(p, p + cs_len, 2)]
            p += cs_len
            comp = body[p]
            p += 1 + comp
            if p + 2 <= len(body):
                ext_len = struct.unpack(">H", body[p:p + 2])[0]
                p += 2
                end = min(p + ext_len, len(body))
                while p + 4 <= end:
                    et, el = struct.unpack(">HH", body[p:p + 4])
                    ed = body[p + 4:p + 4 + el]
                    p += 4 + el
                    if et == 16 and len(ed) >= 2:      # ALPN
                        q, names = 2, []
                        while q < len(ed):
                            n = ed[q]
                            names.append(ed[q + 1:q + 1 + n].decode("latin1"))
                            q += 1 + n
                        out["alpn_client"] = names
                    elif et == 43:                     # supported_versions
                        out["versions"] = [ed[j:j + 2].hex()
                                           for j in range(1, 1 + ed[0], 2)]
        elif htype == 2 and len(body) >= 34:        # ServerHello
            out["cipher_server"] = body[34:36].hex() if len(body) > 36 else None
            p = 34 + 1 + body[34]
            if p + 1 <= len(body):
                p += 1
            if p + 2 <= len(body):
                ext_len = struct.unpack(">H", body[p:p + 2])[0]
                p += 2
                end = min(p + ext_len, len(body))
                while p + 4 <= end:
                    et, el = struct.unpack(">HH", body[p:p + 4])
                    ed = body[p + 4:p + 4 + el]
                    p += 4 + el
                    if et == 16 and len(ed) >= 3:      # ALPN selected
                        n = ed[2]
                        out["alpn_server"] = ed[3:3 + n].decode("latin1")
                    elif et == 43:
                        out["version_server"] = ed[:2].hex()
    return out


def main() -> int:
    up = bytearray()
    down = bytearray()
    timeline = []
    t0 = None
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
            if (src, sport, dst, dport) != TARGET:
                continue
            t0 = t0 if t0 is not None else ts
            timeline.append((ts - t0, direction, len(payload),
                             payload[0] if payload else 0))
            if direction == "t":
                up += payload
            else:
                down += payload

    print("up=%dB down=%dB" % (len(up), len(down)))
    facts = parse_hs(bytes(up[5:5 + int.from_bytes(up[3:5], "big")])
                     if up and up[0] == 0x16 else b"")
    print("\n--- ClientHello ---")
    for k in ("alpn_client", "versions", "ciphers_client"):
        v = facts.get(k)
        if v is None:
            continue
        print("  %-16s %s" % (k, v if k != "ciphers_client"
                              else "%d ciphers: %s"
                              % (len(v), ",".join(v[:10]))))
    print("\n--- ServerHello ---")
    for k in ("alpn_server", "version_server", "cipher_server"):
        print("  %-16s %s" % (k, facts.get(k)))

    print("\n--- TLS record timeline (dir, type, len) ---")
    seq = " ".join("%s%s%d@%dms" % (d, "CH" if t == 0x16 else
                                    "CCS" if t == 0x14 else
                                    "APP" if t == 0x17 else
                                    "AL" if t == 0x15 else "?", n, ts)
                   for ts, d, n, t in timeline[:40])
    print("  " + seq)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
