#!/usr/bin/env python3
"""Decode the PeerLink passthrough capture: every internet-side flow, in order.

payload_hex is a complete IP packet, so we can parse IP/TCP/UDP ourselves and
recover, without decryption:
  * TLS ClientHello -> SNI, ALPN, versions   (which host the game talks to)
  * plaintext HTTP   -> full request/response (any unencrypted API)
  * flow timeline    -> the ORDER things happen in (what runs before what)
"""
from __future__ import annotations

import csv
import os
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "pcap_new", "passthrough_capture.csv")

sys.path.insert(0, HERE)
try:
    from ch_alpn import parse_chello
except Exception:                                   # standalone fallback
    parse_chello = None


def ip_payload(raw: bytes):
    """-> (proto, src, sport, dst, dport, payload)"""
    if len(raw) < 20 or (raw[0] >> 4) != 4:
        return None
    ihl = (raw[0] & 0xF) * 4
    proto = raw[9]
    src = socket.inet_ntoa(raw[12:16])
    dst = socket.inet_ntoa(raw[16:20])
    if proto == 6 and len(raw) >= ihl + 20:          # TCP
        th = raw[ihl:]
        sport, dport = struct.unpack(">HH", th[0:4])
        off = ((th[12] >> 4) & 0xF) * 4
        return 6, src, sport, dst, dport, th[off:]
    if proto == 17 and len(raw) >= ihl + 8:          # UDP
        uh = raw[ihl:]
        sport, dport = struct.unpack(">HH", uh[0:4])
        return 17, src, sport, dst, dport, uh[8:]
    return proto, src, 0, dst, 0, raw[ihl:]


def dns_qname(payload: bytes):
    """-> queried name from a plaintext DNS query packet"""
    try:
        if len(payload) < 12 or struct.unpack(">H", payload[4:6])[0] != 1:
            return None
        i, labels = 12, []
        while i < len(payload):
            n = payload[i]
            if n == 0:
                break
            if n & 0xC0:
                return None
            labels.append(payload[i + 1:i + 1 + n].decode("latin1"))
            i += 1 + n
        return ".".join(labels) or None
    except Exception:
        return None


def flow_key(proto, src, sport, dst, dport):
    a, b = (src, sport), (dst, dport)
    return (proto,) + tuple(sorted((a, b)))


def main() -> int:
    flows = {}
    events = []
    t0 = None

    with open(CSV_PATH, "r", errors="replace") as f:
        rows = (l for l in f if not l.startswith("#"))
        for r in csv.reader(rows):
            if len(r) < 9 or not r[0].isdigit():
                if r and r[0].startswith("# event"):
                    events.append(" ".join(r))
                continue
            ts = int(r[0])
            t0 = t0 if t0 is not None else ts
            direction, proto = r[1], r[2]
            raw = bytes.fromhex(r[8])
            p = ip_payload(raw)
            if not p:
                continue
            pr, src, sport, dst, dport, payload = p
            key = flow_key(pr, src, sport, dst, dport)
            fl = flows.setdefault(key, {
                "proto": pr, "src": src, "sport": sport,
                "dst": dst, "dport": dport, "events": [],
                "timeline": [], "bytes": 0, "sni": None,
                "alpn": None, "http": [], "first": b"",
            })
            fl["bytes"] += len(payload)
            if not fl["first"]:
                fl["first"] = payload[:24]
            ts_rel = ts - t0
            fl["timeline"].append((ts_rel, direction, len(payload)))

            if payload and payload[0] == 0x16 and parse_chello:
                fl.setdefault("hsbuf", b"")
                if len(fl["hsbuf"]) < 2048:
                    fl["hsbuf"] += payload
                buf = fl["hsbuf"]
                if len(buf) >= 5 and buf[5] == 0x01:
                    ln = struct.unpack(">H", buf[3:5])[0]
                    try:
                        res = parse_chello(buf[5:5 + ln]) or {}
                    except Exception:
                        res = {}
                    fl["sni"] = res.get("sni") or fl["sni"]
                    fl["alpn"] = res.get("alpn") or fl["alpn"]
            if payload[:4] in (b"GET ", b"POST", b"HTTP", b"PUT ", b"HEAD"):
                txt = payload.split(b"\r\n")[0].decode("latin1", "replace")
                fl["http"].append(txt)
            if pr == 17 and (sport == 53 or dport == 53):
                q = dns_qname(payload)
                if q:
                    fl.setdefault("dns", set()).add(q)

    print("=" * 78)
    print("internet-side flows: %d   (t0=0 at capture start)" % len(flows))
    print("=" * 78)

    tcp = [f for f in flows.values() if f["proto"] == 6]
    udp = [f for f in flows.values() if f["proto"] == 17]

    for label, group in (("TCP", tcp), ("UDP", udp)):
        print("\n---- %s (%d flows) ----" % (label, len(group)))
        for fl in sorted(group, key=lambda x: x["timeline"][0][0]):
            name = fl["sni"] or ""
            if not name:
                try:
                    name = socket.gethostbyaddr(fl["dst"])[0]
                except Exception:
                    name = "-"
            print("  %5dms  %s:%d -> %s:%d  %-28s %6dB  alpn=%s" % (
                fl["timeline"][0][0], fl["src"], fl["sport"],
                fl["dst"], fl["dport"], name, fl["bytes"], fl["alpn"]))
            if fl["sni"]:
                print("            SNI = %s" % fl["sni"])
            for q in sorted(fl.get("dns", [])):
                print("            DNS   %s" % q)
            for h in fl["http"][:4]:
                print("            HTTP  %s" % h)
            seq = " ".join("%s%d@%d" % (d, n, t) for t, d, n
                           in fl["timeline"][:12])
            print("            %s" % seq)

    if events:
        print("\n---- event markers ----")
        for e in events[:40]:
            print("  " + e)

    # who got the most traffic?
    print("\n---- top talkers ----")
    for fl in sorted(flows.values(), key=lambda x: -x["bytes"])[:10]:
        print("  %8dB  %s:%d -> %s:%d  %s" % (
            fl["bytes"], fl["src"], fl["sport"], fl["dst"], fl["dport"],
            fl["sni"] or "-"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
