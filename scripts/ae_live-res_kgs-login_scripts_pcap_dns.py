#!/usr/bin/env python3
"""Extract plaintext DNS from the PCAPdroid capture -- what did the phone's
resolver actually return for the game hosts?"""
from __future__ import annotations

import collections
import socket
import sys

import dpkt

PCAP = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
        r"\168ed698-75b8-4a9d-8e53-a7c6570a633e"
        r"\PCAPdroid_29_Sep_10_31_15.pcap")


def dec_name(b: bytes, i: int) -> tuple[str, int]:
    out = []
    while True:
        n = b[i]
        if n == 0:
            return ".".join(out), i + 1
        if n & 0xC0 == 0xC0:
            ptr = int.from_bytes(b[i:i + 2], "big") & 0x3FFF
            nm, _ = dec_name(b, ptr)
            out.append(nm)
            return ".".join(out), i + 2
        out.append(b[i + 1:i + 1 + n].decode(errors="replace"))
        i += 1 + n


def main() -> int:
    qa = collections.defaultdict(list)
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
            udp = ip.data
            if not isinstance(udp, dpkt.udp.UDP) or udp.sport != 53 and udp.dport != 53:
                continue
            d = udp.data
            if len(d) < 12:
                continue
            try:
                flags = int.from_bytes(d[2:4], "big")
                qd = int.from_bytes(d[4:6], "big")
                an = int.from_bytes(d[6:8], "big")
                i = 12
                qname = ""
                for _ in range(qd):
                    qname, i = dec_name(d, i)
                    i += 4
                is_resp = bool(flags & 0x8000)
                rcode = flags & 0xF
                if not is_resp:
                    continue
                ans = []
                j = i
                for _ in range(an):
                    nm, j = dec_name(d, j)
                    typ = int.from_bytes(d[j:j + 2], "big")
                    ttl = int.from_bytes(d[j + 4:j + 8], "big")
                    rdlen = int.from_bytes(d[j + 10:j + 12], "big")
                    rd = d[j + 12:j + 12 + rdlen]
                    if typ == 1 and rdlen == 4:
                        ans.append("A %s" % socket.inet_ntoa(rd))
                    elif typ == 5:
                        nm2, _ = dec_name(d, j + 12)
                        ans.append("CNAME %s" % nm2)
                    elif typ == 28 and rdlen == 16:
                        ans.append("AAAA %s" % socket.inet_ntop(socket.AF_INET6, rd))
                    else:
                        ans.append("type%d" % typ)
                    j += 12 + rdlen
                if ans or "konami" in qname:
                    qa[qname.lower()].append((ts, rcode, ans))
            except Exception as e:
                continue

    print("== DNS answers (konami + notable) ==")
    for name in sorted(qa):
        if "konami" not in name and "pes" not in name:
            continue
        seen = collections.Counter()
        first = qa[name][0][0]
        for _, _, ans in qa[name]:
            seen[tuple(ans)] += 1
        print("  %-45s %s" % (name, dict(seen)))

    print("\n== every distinct qname ==")
    for name in sorted(qa):
        print("   %-50s n=%d" % (name, len(qa[name])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
