#!/usr/bin/env python3
"""Inspect the PCAPdroid capture: what's plaintext, what's TLS, any gRPC."""
from __future__ import annotations

import collections
import struct
import sys

import dpkt

PCAP = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
        r"\168ed698-75b8-4a9d-8e53-a7c6570a633e"
        r"\PCAPdroid_29_Sep_10_31_15.pcap")


def main() -> int:
    flows = collections.Counter()
    plaintext = []
    tls_sni = collections.Counter()
    n = 0
    with open(PCAP, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)
        for ts, buf in pcap:
            n += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                try:
                    ip = dpkt.ip.IP(buf)
                except Exception:
                    continue
                eth = None
            ip = eth.data if eth is not None else None
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                flows[("%s->%s" % (ip.src, ip.dst), "udp/tcp?", tcp.__class__.__name__)] += 1
                continue
            key = ("%s:%s -> %s:%s" % (
                dpkt.inet.ntop(ip.__class__.__class__ and (4 if isinstance(ip, dpkt.ip.IP) else 6), ip.src)
                if False else "%s" % (ip.src,),
                tcp.sport, ip.dst, tcp.dport))
            flows[key] += len(tcp.data)
            if not tcp.data:
                continue
            d = tcp.data
            if d.startswith(b"HTTP/") or d[:4] in (b"POST", b"GET ", b"PUT ", b"HEA"):
                plaintext.append(d[:400])
            # TLS record detection
            if d[0] in (0x14, 0x15, 0x16, 0x17) and len(d) > 5 and d[1] == 0x03:
                # find SNI in handshake
                if d[0] == 0x16:
                    i = d.find(b"\x00\x00")
                    sni = _sni(d)
                    if sni:
                        tls_sni[sni] += 1
    print("packets:", n)
    print("\n== top flows (bytes) ==")
    for k, v in flows.most_common(20):
        print("  %8d  %s" % (v, k))
    print("\n== SNI ==")
    for k, v in tls_sni.most_common(30):
        print("  %4d  %s" % (v, k))
    print("\n== plaintext HTTP (%d) ==" % len(plaintext))
    for p in plaintext[:20]:
        print("  ---", p[:300])
    return 0


def _sni(d: bytes) -> str | None:
    # crude: look for server_name extension type 0x0000 with host_name
    idx = d.find(b"\x00\x00\x00")
    while idx != -1:
        # extension: type(2) len(2)
        if idx + 4 <= len(d):
            ln = int.from_bytes(d[idx + 2:idx + 4], "big")
            ext = d[idx + 4:idx + 4 + ln]
            if ext[:1] == b"\x00":  # server_name
                try:
                    nlen = int.from_bytes(ext[3:5], "big")
                    name = ext[5:5 + nlen]
                    if 3 <= nlen <= 100 and name.isascii() and b"." in name:
                        return name.decode()
                except Exception:
                    pass
        idx = d.find(b"\x00\x00\x00", idx + 1)
    return None


if __name__ == "__main__":
    sys.exit(main())
