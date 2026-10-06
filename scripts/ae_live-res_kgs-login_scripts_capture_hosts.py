#!/usr/bin/env python3
"""Ground truth from the capture: every host the app actually contacted.

TLS ClientHello SNI is plaintext, and DNS answers are plaintext.  Together
they map every IP in the capture to a hostname -- so we can see exactly
where the app sends its login traffic instead of guessing.
"""
from __future__ import annotations

import csv
import os
import socket
import struct
import sys

ROOT = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
        r"\peerlink_work\captures\match-2026-09-26")


def read_name(p: bytes, i: int) -> tuple[str, int]:
    out, jumps, guard = [], 0, 0
    while i < len(p) and guard < 24:
        guard += 1
        ln = p[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 == 0xC0:
            i = ((ln & 0x3F) << 8) | p[i + 1]
            jumps += 1
            if jumps > 8:
                break
            continue
        i += 1
        out.append(p[i:i + ln].decode("latin1", "replace"))
        i += ln
    return ".".join(out), i


def dns_answers(p: bytes):
    """(query name, [answer IPs])"""
    if len(p) < 12:
        return None
    qd, an = struct.unpack(">HH", p[4:8])
    i = 12
    qname = ""
    for _ in range(qd):
        nm, i = read_name(p, i)
        if not qname:
            qname = nm
        i += 4
    ips = []
    for _ in range(an):
        nm, i = read_name(p, i)
        if i + 10 > len(p):
            break
        typ, cls, ttl, rdlen = struct.unpack(">HHIH", p[i:i + 10])
        i += 10
        rdata = p[i:i + rdlen]
        i += rdlen
        if typ == 1 and len(rdata) == 4:
            ips.append(socket.inet_ntoa(rdata))
    return qname, ips


def sni_from_record(p: bytes) -> str:
    """Find a TLS ClientHello in p and return its SNI."""
    # hunt for a TLS handshake record: 0x16 0x03 0x01..0x03
    for i in range(0, min(len(p) - 6, 4096)):
        if p[i] != 0x16 or p[i + 1] != 0x03:
            continue
        ln = (p[i + 3] << 8) | p[i + 4]
        if ln < 40 or i + 5 + ln > len(p):
            continue
        rec = p[i + 5:i + 5 + ln]
        if not rec or rec[0] != 0x01:      # handshake type = ClientHello
            continue
        try:
            j = 4 + 2 + 32                  # hdr + ver + random
            sl = rec[j]
            j += 1 + sl                     # session id
            cl = (rec[j] << 8) | rec[j + 1]
            j += 2 + cl                     # cipher suites
            al = rec[j]
            j += 1 + al                     # compression methods
            el = (rec[j] << 8) | rec[j + 1]
            j += 2
            end = j + el
            while j + 4 <= end:
                t = (rec[j] << 8) | rec[j + 1]
                l = (rec[j + 2] << 8) | rec[j + 3]
                body = rec[j + 4:j + 4 + l]
                if t == 0 and len(body) >= 5:      # server_name
                    nl = (body[3] << 8) | body[4]
                    return body[5:5 + nl].decode("ascii", "replace")
                j += 4 + l
        except Exception:
            continue
    return ""


def main() -> int:
    name2ip = {}
    ip2name = {}
    sni_by_flow = {}
    host_by_flow = {}

    for dev in sorted(os.listdir(ROOT)):
        p = os.path.join(ROOT, dev, "passthrough_capture.csv")
        if not os.path.isfile(p):
            continue
        with open(p, newline="", encoding="utf-8", errors="replace") as f:
            rows = csv.DictReader(r for r in f if not r.startswith("#"))
            for r in rows:
                try:
                    proto = (r.get("proto") or "").strip()
                    dst = (r.get("dst") or "").strip()
                    sport = (r.get("sport") or "").strip()
                    dport = int(r.get("dport") or 0)
                    ph = (r.get("payload_hex") or "").strip()
                except Exception:
                    continue
                if not ph:
                    continue
                try:
                    b = bytes.fromhex(ph)
                except Exception:
                    continue
                if proto == "udp" and dport == 53 and len(b) > 12:
                    try:
                        qn, ips = dns_answers(b)
                    except Exception:
                        continue
                    if qn and ips:
                        name2ip.setdefault(qn, set()).update(ips)
                        for ip in ips:
                            ip2name.setdefault(ip, set()).add(qn)
                if proto == "tcp" and dport in (443, 8443) and len(b) > 40:
                    s = sni_from_record(b)
                    if s:
                        key = (dev, sport, dst)
                        sni_by_flow[key] = s
                        ip2name.setdefault(dst, set()).add(s)

    print("=== DNS name -> IPs ===")
    for n, ips in sorted(name2ip.items()):
        print(f"  {n:48s} {sorted(ips)}")

    print("\n=== TLS SNI seen on each destination IP ===")
    for (dev, sport, dst), s in sorted(sni_by_flow.items(),
                                       key=lambda x: x[0][2]):
        print(f"  {dst:18s} sport={sport:6s} SNI={s}")

    print("\n=== destination IP -> hostnames (from DNS + SNI) ===")
    for ip, names in sorted(ip2name.items(), key=lambda x: -len(x[1])):
        try:
            rev = socket.gethostbyaddr(ip)[0]
        except Exception:
            rev = ""
        alln = " , ".join(sorted(names))
        print(f"  {ip:18s} {alln:60s} rev={rev}")

    # high-traffic destinations with no name yet
    return 0


if __name__ == "__main__":
    sys.exit(main())
