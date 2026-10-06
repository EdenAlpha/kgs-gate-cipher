#!/usr/bin/env python3
"""Correlate each TCP flow with the SNI from its ClientHello; report bytes both ways,
handshake cipher/ALPN, and whether a 502-style empty response came back."""
from __future__ import annotations

import collections
import socket
import struct
import sys

import dpkt

PCAP = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
        r"\168ed698-75b8-4a9d-8e53-a7c6570a633e"
        r"\PCAPdroid_29_Sep_10_31_15.pcap")


def ipstr(b: bytes) -> str:
    return socket.inet_ntoa(b) if len(b) == 4 else b.hex()


def parse_clienthello(d: bytes):
    """Return (sni, alpn_list, ciphers) from a TLS ClientHello record, else None."""
    if len(d) < 6 or d[0] != 0x16 or d[1] != 0x03:
        return None
    rec_len = int.from_bytes(d[3:5], "big")
    hs = d[5:5 + rec_len]
    if len(hs) < 4 or hs[0] != 0x01:
        return None
    body = hs[4:]
    try:
        i = 2 + 32  # version + random
        sess_len = body[i]; i += 1 + sess_len
        cs_len = int.from_bytes(body[i:i + 2], "big"); i += 2
        ciphers = [body[j:j + 2].hex() for j in range(i, i + cs_len, 2)]
        i += cs_len
        comp_len = body[i]; i += 1 + comp_len
        ext_len = int.from_bytes(body[i:i + 2], "big"); i += 2
        end = i + ext_len
        sni = None
        alpn = []
        while i + 4 <= end:
            t = int.from_bytes(body[i:i + 2], "big")
            l = int.from_bytes(body[i + 2:i + 4], "big")
            v = body[i + 4:i + 4 + l]
            if t == 0 and len(v) >= 5:
                nl = int.from_bytes(v[3:5], "big")
                sni = v[5:5 + nl].decode(errors="replace")
            elif t == 16:
                j = 2
                while j < len(v):
                    n = v[j]; j += 1
                    alpn.append(v[j:j + n].decode(errors="replace")); j += n
            i += 4 + l
        return sni, alpn, ciphers
    except Exception:
        return None


def main() -> int:
    flows = {}
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
            a = (ipstr(ip.src), tcp.sport)
            b = (ipstr(ip.dst), tcp.dport)
            # normalize: client = lower port? use sni detection instead
            key = tuple(sorted([a, b]))
            fl = flows.setdefault(key, {
                "sni": None, "alpn": None, "c2s": 0, "s2c": 0,
                "first": ts, "last": ts, "c2s_pkts": 0, "s2c_pkts": 0,
                "payloads": [],
            })
            fl["last"] = max(fl["last"], ts)
            fl["first"] = min(fl["first"], ts)
            if not tcp.data:
                continue
            ch = parse_clienthello(tcp.data)
            if ch:
                fl["sni"], fl["alpn"], fl["ciphers"] = ch
            # direction: who sent the ClientHello is the client
            src_is_client = (a == key[0] and (fl["sni"] is None or True))
            # decide by port: server port is 443/80 typically
            if b[1] in (443, 80, 8080):
                fl["c2s"] += len(tcp.data); fl["c2s_pkts"] += 1
                fl["payloads"].append(("c", tcp.data))
            elif a[1] in (443, 80, 8080):
                fl["s2c"] += len(tcp.data); fl["s2c_pkts"] += 1
                fl["payloads"].append(("s", tcp.data))
            else:
                fl["c2s"] += len(tcp.data)

    print("flows:", len(flows))
    rows = sorted(flows.items(), key=lambda kv: -(kv[1]["c2s"] + kv[1]["s2c"]))
    for key, fl in rows[:40]:
        alpn = ",".join(fl.get("alpn") or []) or "-"
        print("  %-40s sni=%-38s c2s=%-7d s2c=%-7d dur=%.1fs alpn=%s" % (
            "%s:%s-%s:%s" % (key[0][0], key[0][1], key[1][0], key[1][1]),
            fl["sni"] or "-", fl["c2s"], fl["s2c"],
            fl["last"] - fl["first"], alpn))

    # Deep dive: pes22-game flows -- look at first server app-data frames
    print("\n== pes22-game flows detail ==")
    for key, fl in flows.items():
        if fl["sni"] != "pes22-game.cs.konami.net":
            continue
        print("  flow %s:%s-%s:%s  c2s=%d s2c=%d  t0=%s  alpn=%s" % (
            key[0][0], key[0][1], key[1][0], key[1][1],
            fl["c2s"], fl["s2c"], fl["first"], fl.get("alpn")))
        for d, p in fl["payloads"][:8]:
            print("     %s %s len=%d head=%s" % (
                d, "tls" if p[0] in (0x14, 0x15, 0x16, 0x17) else "raw",
                len(p), p[:24].hex()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
