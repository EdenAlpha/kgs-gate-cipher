#!/usr/bin/env python3
"""Tight focus: what the internet side did in the seconds around each stall.

Also builds ip->hostname from DNS answers so flows get real names.
"""
from __future__ import annotations

import csv
import io
import socket
import struct
import sys
from collections import defaultdict

ROOT = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work\captures\match-2026-09-26"
T0 = 1790385845048

STALLS = [
    (1790386488724, 1790386509746, "stall1"),
    (1790386635917, 1790386656938, "stall2"),
    (1790387153392, 1790387174409, "stall3"),
]


def wall(ts: int) -> str:
    ms = ts - T0
    h, rem = divmod(ms, 3600000)
    m, rem = divmod(rem, 60000)
    s, msec = divmod(rem, 1000)
    return f"{h:02d}:{m:02d}:{s:02d}.{msec:03d}"


def dns_name(buf, off):
    labels, seen, start = [], 0, off
    ptr = None
    while off < len(buf) and seen < 60:
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if ptr is None:
                ptr = off + 2
            off = ((ln & 0x3F) << 8) | buf[off + 1]
            seen += 1
            continue
        off += 1
        if off + ln > len(buf):
            break
        labels.append(buf[off:off + ln].decode("latin1", "replace"))
        off += ln
        seen += 1
    return ".".join(labels), (ptr if ptr is not None else off)


def parse_dns_full(body):
    """-> (qname, [(rtype, rdata_str), ...])"""
    if len(body) < 12:
        return "", []
    _id, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", body, 0)
    qr = (flags >> 15) & 1
    off = 12
    qname = ""
    if qd:
        qname, off = dns_name(body, off)
        off += 4
    answers = []
    if not qr:
        return qname, answers
    for _ in range(min(an, 12)):
        _n, off = dns_name(body, off)
        if off + 10 > len(body):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", body, off)
        off += 10
        rd = body[off:off + rdlen]
        off += rdlen
        if rtype == 1 and len(rd) == 4:
            answers.append((1, socket.inet_ntoa(rd)))
        elif rtype == 28 and len(rd) == 16:
            answers.append((28, socket.inet_ntop(socket.AF_INET6, rd)))
        elif rtype == 5:
            nm, _ = dns_name(body, off - rdlen)
            answers.append((5, nm))
        elif rtype == 16:
            try:
                answers.append((16, rd.split(b"\x00")[0].decode()))
            except Exception:
                pass
    return qname, answers


def parse_udp_payload(body, sport, dport):
    if 53 in (sport, dport):
        return ("dns",) + parse_dns_full(body)
    if 443 in (sport, dport) and len(body) > 5 and body[0] == 0x16:
        return ("tls", "", [])
    return ("", "", [])


def load(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            rows.append(line)
    out = []
    for r in csv.DictReader(io.StringIO("".join(rows))):
        try:
            ts = int(r["ts_ms"])
        except (TypeError, ValueError):
            continue
        try:
            p = bytes.fromhex(r.get("payload_hex", ""))
        except ValueError:
            continue
        if len(p) < 20:
            continue
        ver = p[0] >> 4
        if ver == 4:
            ihl = (p[0] & 0xF) * 4
            proto = p[9]
            src = socket.inet_ntoa(p[12:16])
            dst = socket.inet_ntoa(p[16:20])
            l4 = p[ihl:]
        elif ver == 6:
            proto = p[6]
            src = socket.inet_ntop(socket.AF_INET6, p[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, p[24:40])
            l4 = p[40:]
        else:
            continue
        sport = dport = 0
        flags = ""
        if proto == 17 and len(l4) >= 8:
            sport, dport, ulen, _ = struct.unpack_from(">HHHH", l4, 0)
            body = l4[8:ulen] if ulen >= 8 else l4[8:]
        elif proto == 6 and len(l4) >= 20:
            sport, dport = struct.unpack_from(">HH", l4, 0)
            doff = (l4[12] >> 4) * 4
            f = l4[13]
            flags = "".join(c for bit, c in ((0x02, "S"), (0x10, "A"),
                                             (0x01, "F"), (0x04, "R"),
                                             (0x08, "P")) if f & bit)
            body = l4[doff:] if doff <= len(l4) else b""
        else:
            body = b""
        kind, name, ans = ("", "", [])
        if proto == 17:
            kind, name, ans = parse_udp_payload(body, sport, dport)
        out.append(dict(ts=ts, dir=r["dir"], proto=proto, src=src, sport=sport,
                        dst=dst, dport=dport, flags=flags, kind=kind,
                        name=name, ans=ans, n=len(p), _payload=body))
    return out


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "z1-tiamant-client"
    recs = load(f"{ROOT}\\{which}\\passthrough_capture.csv")
    print(f"=== {which} packets={len(recs)} ===")

    ip2name = defaultdict(set)
    for r in recs:
        if r["kind"] == "dns" and r["ans"]:
            for rt, val in r["ans"]:
                if rt == 1 or rt == 28:
                    ip2name[val].add(r["name"])

    print("\n--- resolved endpoints ---")
    for ip, names in sorted(ip2name.items()):
        print(f"  {ip:<40s} {'; '.join(sorted(names))}")

    def nm(ip):
        n = ip2name.get(ip)
        return sorted(n)[0] if n else ""

    for s, e, tag in STALLS:
        lo, hi = s - 20000, e + 12000
        print(f"\n############ {tag}  {wall(s)} .. {wall(e)}  ############")
        print("  per-second traffic to key remotes (t=out r=in):")
        secs = defaultdict(lambda: defaultdict(int))
        for r in recs:
            if not (lo <= r["ts"] <= hi):
                continue
            remote = r["dst"] if r["dir"] == "t" else r["src"]
            secs[int((r["ts"] - T0) / 1000)][(r["dir"], remote)] += 1
        remotes = set()
        for sd in secs.values():
            for k in sd:
                remotes.add(k)
        key = sorted({rm for _d, rm in remotes},
                     key=lambda x: -sum(secs[k][(d, x)]
                                        for k in secs for d, _ in [(k, 0)])
                     if False else 0)
        # choose top remotes by total volume
        tot = defaultdict(int)
        for sd in secs.values():
            for (d, rm), c in sd.items():
                tot[rm] += c
        top = sorted(tot, key=lambda x: -tot[x])[:7]
        print("      sec | " + " | ".join(f"{nm(x) or x[:14]}"[:16]
                                          for x in top))
        for sec in sorted(secs):
            if sec % 1:
                pass
            row = []
            for rm in top:
                a = secs[sec][("t", rm)]
                b = secs[sec][("r", rm)]
                row.append(f"{a}/{b}")
            mark = ""
            for ss, ee, _ in STALLS:
                if ss - T0 <= sec * 1000 <= ee - T0:
                    mark = " *"
            print(f"      {sec:6d} | " + " | ".join(f"{v:>16}" for v in row)
                  + mark)

        print(f"  full packet timeline {wall(lo)} -> {wall(hi)}:")
        for r in recs:
            if not (lo <= r["ts"] <= hi):
                continue
            tag2 = ""
            if s <= r["ts"] <= e:
                tag2 = "  <<<STALL>>>"
            elif 0 < s - r["ts"] <= 6000:
                tag2 = "  <<PRE>>"
            src = f"{r['src']}:{r['sport']}"
            dst = f"{r['dst']}:{r['dport']}"
            extra = r["name"] or ""
            if r["kind"] == "dns":
                extra = f"DNS {r['name']} -> " + ",".join(v for _t, v in r["ans"][:4])
            print(f"    {wall(r['ts'])} {r['dir']} {r['proto']:<4} "
                  f"{src:<24} {dst:<24} {r['flags']:<4} {extra}{tag2}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
