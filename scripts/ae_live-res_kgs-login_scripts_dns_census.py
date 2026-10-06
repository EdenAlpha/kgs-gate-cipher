#!/usr/bin/env python3
"""Every DNS query name and every TCP destination the phones used."""
from __future__ import annotations

import csv
import os
import socket
import struct
import sys

ROOT = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
        r"\peerlink_work\captures\match-2026-09-26")


def dns_name(payload: bytes, i: int) -> str:
    out, jumps = [], 0
    while i < len(payload):
        ln = payload[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 == 0xC0:
            if i + 1 >= len(payload):
                break
            i = ((ln & 0x3F) << 8) | payload[i + 1]
            jumps += 1
            if jumps > 8:
                break
            continue
        i += 1
        out.append(payload[i:i + ln].decode("latin1", "replace"))
        i += ln
    return ".".join(out)


def main() -> int:
    names: dict[str, int] = {}
    tcp: dict[tuple[str, int], int] = {}
    udp: dict[tuple[str, int], int] = {}
    for d in os.listdir(ROOT):
        p = os.path.join(ROOT, d, "passthrough_capture.csv")
        if not os.path.isfile(p):
            continue
        with open(p, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(r for r in f
                                      if not r.startswith("#")):
                try:
                    proto = (row.get("proto") or "").strip()
                    dst = (row.get("dst") or "").strip()
                    dp = int(row.get("dport") or 0)
                    ph = (row.get("payload_hex") or "").strip()
                except Exception:
                    continue
                if proto == "tcp" and dp == 443:
                    tcp[(dst, dp)] = tcp.get((dst, dp), 0) + 1
                elif proto == "udp" and dp == 53 and ph:
                    b = bytes.fromhex(ph)
                    if len(b) > 12:
                        q = dns_name(b, 12)
                        if q:
                            names[q] = names.get(q, 0) + 1
                elif proto == "udp" and dp not in (53,):
                    udp[(dst, dp)] = udp.get((dst, dp), 0) + 1

    print("=== DNS query names ===")
    for n, c in sorted(names.items(), key=lambda x: -x[1]):
        print(f"  {c:5d}  {n}")

    print("\n=== TCP :443 destinations (IP -> name) ===")
    ip2name = {}
    for (ip, _), c in sorted(tcp.items(), key=lambda x: -x[1]):
        try:
            nm = socket.gethostbyaddr(ip)[0]
        except Exception:
            nm = "?"
        ip2name[ip] = nm
        print(f"  {c:5d}  {ip:16s} {nm}")

    print("\n=== other UDP destinations ===")
    for (ip, port), c in sorted(udp.items(), key=lambda x: -x[1])[:40]:
        print(f"  {c:5d}  {ip:16s} :{port}")

    import json
    with open("ip2name_z.json", "w") as f:
        json.dump(ip2name, f, indent=1)
    print("\nwrote ip2name_z.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
