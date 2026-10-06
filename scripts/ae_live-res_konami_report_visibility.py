"""konami_report_visibility.py -- is Konami's disconnect reporting visible to a
VPN, and is it encrypted?

Reads captures/*/passthrough_capture.csv (written by PeerLink's VpnService) and
answers, from the packets alone:

  1. which Konami hosts are contacted, on which port, encrypted or not
  2. every plaintext HTTP request line (reassembled by TCP sequence number)
  3. whether a plaintext report coincides with each observed 0pps_cliff stall
  4. the full decoded body of the report that precedes the first stall

Usage:  python konami_report_visibility.py [capture.csv]
"""

import csv
import re
import socket
import struct
import collections
import urllib.parse
import glob
import sys

from reassemble import http_messages, decode, hms, safe

DEFAULT = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"


def read_name(b, i, depth=0):
    out = []
    if depth > 8:
        return "", i
    while i < len(b):
        l = b[i]
        if l == 0:
            i += 1
            break
        if l & 0xC0 == 0xC0:
            ptr = ((l & 0x3F) << 8) | b[i + 1]
            n, _ = read_name(b, ptr, depth + 1)
            out.append(n)
            i += 2
            break
        i += 1
        out.append(b[i:i + l].decode("latin-1", "replace"))
        i += l
    return ".".join(out), i


def load(path):
    a2n = collections.defaultdict(set)
    ports = collections.Counter()
    events = []
    payload_by_dp = collections.Counter()
    for row in csv.reader(open(path, newline="", encoding="utf-8", errors="replace")):
        if not row:
            continue
        if row[0].startswith("# event"):
            parts = row[0].split()
            if len(parts) > 2 and parts[2].isdigit():
                events.append((int(parts[2]), " ".join(parts[2:])))
            continue
        if row[0].startswith("#") or row[0] == "ts_ms" or len(row) < 9:
            continue
        ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
        try:
            pb = bytes.fromhex(hexs)
        except Exception:
            continue
        if proto == "udp" and int(sport) == 53:
            dns = pb[28:]
            if len(dns) >= 12:
                qd, an = struct.unpack("!HH", dns[4:8])
                i = 12
                for _ in range(qd):
                    _, i = read_name(dns, i)
                    i += 4
                for _ in range(an):
                    nm, i = read_name(dns, i)
                    typ, cls, ttl, rdlen = struct.unpack("!HHIH", dns[i:i + 10])
                    i += 10
                    rd = dns[i:i + rdlen]
                    i += rdlen
                    if typ == 1 and rdlen == 4:
                        a2n[socket.inet_ntoa(rd)].add(nm)
        elif proto == "tcp":
            ports[(d, int(dport))] += 1
    return a2n, ports, sorted(events)


def main(path):
    a2n, ports, events = load(path)
    msgs = http_messages(path)

    print("=" * 78)
    print("capture: %s" % path)
    print("=" * 78)

    # 1. plaintext HTTP endpoints
    hosts = collections.Counter()
    endpoints = collections.Counter()
    for ts, p, h, b in msgs:
        m = re.search(rb"Host: ([^\r\n]+)", h)
        hosts[m.group(1).decode() if m else "?"] += 1
        endpoints[p] += 1
    print("\n[1] PLAINTEXT HTTP (port 80) -- no TLS at all")
    for h, n in hosts.most_common():
        print("      host  %-28s %d request(s)" % (h, n))
        for ip, names in a2n.items():
            if h in names:
                print("            -> %s" % ip)
    for p, n in endpoints.most_common():
        print("      %-45s x%d" % (p, n))
    if not msgs:
        print("      (none)")

    # 2. encrypted side
    print("\n[2] TLS (port 443) -- encrypted, metadata only")
    print("      tcp dport 443 packets: %d ; dport 80 packets: %d ; tcp dir=r rows: %s"
          % (ports[("t", 443)], ports[("t", 80)],
             "yes" if ports.get(("r", 80), 0) else "NO (responses not captured)"))
    print("      konami names resolved in this capture:")
    seen = set()
    for nm in sorted({n for s in a2n.values() for n in s}):
        if "konami" in nm:
            print("        %-34s -> %s" % (nm, sorted(a2n_nm(a2n, nm))))
            seen.add(nm)
    for nm in seen:
        pass

    # 3. stalls vs plaintext reports
    print("\n[3] event markers vs plaintext reports")
    for t, label in events:
        print("      %s  %s" % (hms(t), label))
    cliffs = [t for t, l in events if "0pps_cliff" in l]
    reports = [(ts, p) for ts, p, h, b in msgs if p.endswith("ReportLog.php")]
    print("\n      pairing each stall-onset cliff with the preceding ReportLog:")
    for i in range(0, len(cliffs), 2):
        c = cliffs[i]
        best = None
        for t, p in reports:
            if t <= c and (best is None or t > best[0]):
                best = (t, p)
        if best:
            print("        cliff %s  <-  report %s   (dt = %+.2f s)"
                  % (hms(c), hms(best[0]), (c - best[0]) / 1000.0))

    # 4. full body of the report before the first cliff
    if cliffs:
        c = cliffs[0]
        best = None
        for m in msgs:
            if m[1].endswith("ReportLog.php") and m[0] <= c and (best is None or m[0] > best[0]):
                best = m
        if best:
            t, p, h, b = best
            dat, txt = decode(b)
            print("\n[4] full plaintext body preceding stall #1 "
                  "(%s, dt=%+.2f s, %d bytes)" % (hms(t), (c - t) / 1000.0, len(b)))
            print("      request line: POST %s HTTP/1.1" % p)
            print("      " + safe(h.decode("ascii", "replace")).replace("\r\n", "\n      "))
            print("      --- decoded (%d chars) ---" % (len(dat) if dat else 0))
            print(safe(dat) if dat else txt)


def a2n_nm(a2n, nm):
    return [ip for ip, s in a2n.items() if nm in s]


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT)
