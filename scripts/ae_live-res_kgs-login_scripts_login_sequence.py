#!/usr/bin/env python3
"""Reconstruct the game's login sequence in order, from the capture.

Deliberately walks the traffic strictly first-to-last rather than jumping to the
last thing seen, because the ordering is the information: a login is a sequence,
and which call comes first tells us what bootstraps what.

For every flow, in timestamp order:
  * the TCP handshake, so connections opening and closing are visible;
  * port 80 traffic decoded as HTTP, since that is readable -- and a bootstrap
    config fetched over plaintext HTTP is the one place a route table could
    still be hiding, given it is in none of the shipped artifacts;
  * port 443 flows placed in the sequence by size and timing even though their
    payloads are encrypted;
  * any JSON or config-shaped body, extracted and shown.

The gRPC payloads themselves are encrypted, so this establishes the shape and
order of the login rather than the command names.
"""
from __future__ import annotations

import binascii
import collections
import os
import re
import struct
import sys

CSV = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\pt\passthrough_capture.csv"


def rows(path):
    """Yield (kind, ts, fields, rawline)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                yield ("EVENT", 0, line.strip(), "")
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 9:
                continue
            try:
                yield ("ROW", int(p[0]), p, line)
            except Exception:
                continue


def tcp_of(ip):
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    p = ihl
    if len(ip) < p + 20:
        return None
    sport, dport = struct.unpack(">HH", ip[p:p + 4])
    seq, ack = struct.unpack(">II", ip[p + 4:p + 12])
    doff = (ip[p + 12] >> 4) * 4
    if doff < 20:
        return None
    return dict(sport=sport, dport=dport, seq=seq, ack=ack,
                flags=ip[p + 13], payload=ip[p + doff:])


def main() -> int:
    if not os.path.exists(CSV):
        print("capture not found:", CSV)
        return 1
    flows = collections.OrderedDict()
    http_text = []
    t0 = None
    n = 0
    for kind, ts, p, line in rows(CSV):
        if kind == "EVENT":
            print("\n### %s" % p)
            continue
        n += 1
        if t0 is None:
            t0 = ts
        rel = (ts - t0) / 1000.0
        try:
            ip = binascii.unhexlify(p[8].strip())
        except Exception:
            continue
        t = tcp_of(ip)
        if not t:
            continue
        key = (p[3], t["sport"], p[5], t["dport"])
        f = flows.setdefault(key, {"first": rel, "last": rel, "bytes": 0,
                                   "pkts": 0, "syn": False, "fin": False,
                                   "rst": False,
                                   "dirs": collections.Counter()})
        f["last"] = rel
        f["pkts"] += 1
        f["dirs"][p[1]] += 1
        pay = t["payload"]
        f["bytes"] += len(pay)
        if t["flags"] & 0x02 and not (t["flags"] & 0x10):
            f["syn"] = True
        if t["flags"] & 0x01:
            f["fin"] = True
        if t["flags"] & 0x04:
            f["rst"] = True
        if (t["dport"] == 80 or t["sport"] == 80) and pay:
            txt = pay.decode("latin1", "replace")
            if any(txt.startswith(h) for h in
                   ("GET ", "POST ", "PUT ", "HEAD ", "HTTP/1.")):
                http_text.append((rel, p[1], key, txt))

    span = max((f["last"] for f in flows.values()), default=0)
    print("=" * 78)
    print("FLOW SEQUENCE  (%d packets, %.1f s span)" % (n, span))
    print("=" * 78)
    print("%8s %-44s %7s %6s %s" % ("t_s", "flow", "bytes", "pkts", "state"))
    for key, f in sorted(flows.items(), key=lambda kv: kv[1]["first"]):
        st = []
        if f["syn"]:
            st.append("open")
        if f["fin"]:
            st.append("fin")
        if f["rst"]:
            st.append("RST")
        print("%8.2f %-44s %7d %6d %s"
              % (f["first"], "%s:%d -> %s:%d" % key, f["bytes"], f["pkts"],
                 ",".join(st) or "-"))

    print("\n" + "=" * 78)
    print("PLAINTEXT HTTP, in order  (%d readable messages)" % len(http_text))
    print("=" * 78)
    for rel, d, key, txt in http_text[:60]:
        head = txt.split("\r\n\r\n", 1)[0]
        first = head.split("\r\n")[0]
        host = ""
        for ln in head.split("\r\n")[1:]:
            if ln.lower().startswith("host:"):
                host = ln.split(":", 1)[1].strip()
        print("%8.2f %-3s %-38s %s" % (rel, d, host[:38], first[:66]))

    print("\n" + "=" * 78)
    print("JSON / CONFIG-LIKE BODIES mentioning routes, commands or endpoints")
    print("=" * 78)
    seen = set()
    found = 0
    for rel, d, key, txt in http_text:
        for m in re.finditer(r"\{[^{}]{20,4000}\}", txt):
            s = m.group(0)
            if hash(s) in seen:
                continue
            seen.add(hash(s))
            low = s.lower()
            if any(k in low for k in ("grpc", "command", "route", "path",
                                      "endpoint", "service", "method",
                                      "session", "login")):
                found += 1
                print("\n  t=%.2f %s %s" % (rel, d, key))
                print("  %s" % s[:900])
    if not found:
        print("  (none)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
