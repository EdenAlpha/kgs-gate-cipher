#!/usr/bin/env python3
"""Decode passthrough_capture.csv (complete IP packets in hex) and show
what the game did on the internet side around each stall."""
from __future__ import annotations

import csv
import io
import socket
import struct
import sys
from collections import defaultdict

ROOT = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work\captures\match-2026-09-26"

STALLS = [
    (1790386488724, 1790386509746, "stall1"),
    (1790386635917, 1790386656938, "stall2"),
    (1790387153392, 1790387174409, "stall3"),
]
T0 = 1790385845048          # 02:24:05.048


def wall(ts: int) -> str:
    ms = ts - T0
    h, rem = divmod(ms, 3600000)
    m, rem = divmod(rem, 60000)
    s, msec = divmod(rem, 1000)
    return f"{h:02d}:{m:02d}:{s:02d}.{msec:03d}"


def dns_name(buf: bytes, off: int):
    labels, seen = [], 0
    while off < len(buf) and seen < 60:
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                break
            off = ((ln & 0x3F) << 8) | buf[off + 1]
            seen += 1
            continue
        off += 1
        if off + ln > len(buf):
            break
        labels.append(buf[off:off + ln].decode("latin1", "replace"))
        off += ln
        seen += 1
    return ".".join(labels), off


def parse_dns(payload: bytes):
    if len(payload) < 12:
        return None
    qd = struct.unpack_from(">H", payload, 4)[0]
    off = 12
    qs = []
    for _ in range(min(qd, 8)):
        name, off = dns_name(payload, off)
        if off + 4 > len(payload):
            break
        qtype, _qclass = struct.unpack_from(">HH", payload, off)
        off += 4
        qs.append((name, qtype))
    return qs


def parse_tls_sni(rec: bytes):
    """Best-effort SNI extraction from a TLS record (ClientHello)."""
    try:
        if len(rec) < 42 or rec[0] != 0x16 or rec[1] != 0x03:
            return None
        off = 5                              # record header
        if rec[off] != 0x02:                 # ClientHello
            return None
        off += 4                             # hs type + len
        off += 2                             # client version
        off += 32                            # random
        if off >= len(rec):
            return None
        sid_len = rec[off]
        off += 1 + sid_len
        cs_len = struct.unpack_from(">H", rec, off)[0]
        off += 2 + cs_len
        comp_len = rec[off]
        off += 1 + comp_len
        if off + 2 > len(rec):
            return None
        ext_total = struct.unpack_from(">H", rec, off)[0]
        off += 2
        end = off + ext_total
        while off + 4 <= min(end, len(rec)):
            et, el = struct.unpack_from(">HH", rec, off)
            off += 4
            if et == 0x0000:                 # server_name
                if off + 5 > len(rec):
                    return None
                nlen = struct.unpack_from(">H", rec, off + 3)[0]
                return rec[off + 5:off + 5 + nlen].decode("latin1", "replace")
            off += el
    except Exception:
        return None
    return None


def parse_packet(hx: str):
    """-> (proto, src, sport, dst, dport, extra) or None"""
    try:
        p = bytes.fromhex(hx)
    except ValueError:
        return None
    if len(p) < 20:
        return None
    ver = p[0] >> 4
    if ver == 4:
        ihl = (p[0] & 0xF) * 4
        if ihl < 20 or len(p) < ihl:
            return None
        proto = p[9]
        src = socket.inet_ntoa(p[12:16])
        dst = socket.inet_ntoa(p[16:20])
        l4 = p[ihl:]
    elif ver == 6:
        if len(p) < 40:
            return None
        proto = p[6]
        src = socket.inet_ntop(socket.AF_INET6, p[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, p[24:40])
        l4 = p[40:]
    else:
        return None

    extra = ""
    if proto == 17 and len(l4) >= 8:
        sport, dport, ulen, _ = struct.unpack_from(">HHHH", l4, 0)
        body = l4[8:ulen] if ulen >= 8 else l4[8:]
        if 53 in (sport, dport):
            qs = parse_dns(body)
            if qs:
                extra = "DNS " + ",".join(f"{n}/{t}" for n, t in qs)
        elif 443 in (sport, dport) and len(body) > 5 and body[0] == 0x16:
            sni = parse_tls_sni(body)
            if sni:
                extra = f"TLS SNI={sni}"
        return ("udp", src, sport, dst, dport, extra)
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack_from(">HH", l4, 0)
        doff = (l4[12] >> 4) * 4
        flags = l4[13]
        body = l4[doff:] if doff <= len(l4) else b""
        if 443 in (sport, dport) and body and body[0] == 0x16:
            sni = parse_tls_sni(body)
            if sni:
                extra = f"TLS SNI={sni}"
        fl = []
        if flags & 0x02:
            fl.append("SYN")
        if flags & 0x10:
            fl.append("ACK")
        if flags & 0x01:
            fl.append("FIN")
        if flags & 0x04:
            fl.append("RST")
        if flags & 0x08:
            fl.append("PSH")
        extra = (extra + " " + "|".join(fl)).strip()
        return ("tcp", src, sport, dst, dport, extra)
    if proto in (1, 58):
        return ("icmp", src, 0, dst, 0, "")
    return (f"p{proto}", src, 0, dst, 0, extra)


def load(path: str):
    rows, events = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("# event"):
                events.append(line.strip())
                continue
            if line.startswith("#") or not line.strip():
                continue
            rows.append(line)
    rdr = csv.DictReader(io.StringIO("".join(rows)))
    out = []
    for r in rdr:
        try:
            ts = int(r["ts_ms"])
        except (TypeError, ValueError):
            continue
        pk = parse_packet(r.get("payload_hex", ""))
        if not pk:
            continue
        out.append((ts, r["dir"], r["proto"], pk))
    return out, events


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "z1-tiamant-client"
    path = f"{ROOT}\\{which}\\passthrough_capture.csv"
    recs, events = load(path)
    print(f"=== {which}  packets={len(recs)} ===")
    print(f"window {wall(recs[0][0])} .. {wall(recs[-1][0])}")

    # ---- flow summary -------------------------------------------------
    flows = defaultdict(lambda: [0, 0, None, None, set()])
    for ts, d, p, pk in recs:
        proto, src, sp, dst, dp, extra = pk
        key = (proto, dst if d == "t" else src, dp if d == "t" else sp)
        f = flows[key]
        f[0] += 1
        f[1] += 1
        f[2] = ts if f[2] is None else min(f[2], ts)
        f[3] = ts if f[3] is None else max(f[3], ts)
        if extra:
            f[4].add(extra[:80])
    print("\n--- outbound flow summary (proto, remote, rport) ---")
    for k in sorted(flows, key=lambda k: -flows[k][0]):
        cnt, _, a, b, ex = flows[k]
        if cnt < 3:
            continue
        print(f"  {k[0]:5s} {k[1]:>40s}:{k[2]:<6} n={cnt:<6} "
              f"{wall(a)}..{wall(b)}")
        for e in sorted(ex)[:3]:
            print(f"        {e}")

    # ---- DNS names ----------------------------------------------------
    names = defaultdict(int)
    for ts, d, p, pk in recs:
        if pk[5].startswith("DNS "):
            for part in pk[5][4:].split(","):
                nm = part.rsplit("/", 1)[0]
                names[(nm, d)] += 1
    print("\n--- DNS names ---")
    for (nm, d), c in sorted(names.items(), key=lambda x: -x[1]):
        print(f"  {'->' if d == 't' else '<-'} {nm:<60s} {c}")

    # ---- SNI ----------------------------------------------------------
    snis = defaultdict(int)
    for ts, d, p, pk in recs:
        if "SNI=" in pk[5]:
            snis[pk[5].split("SNI=")[1]] += 1
    print("\n--- TLS SNI ---")
    for n, c in sorted(snis.items(), key=lambda x: -x[1]):
        print(f"  {n:<60s} {c}")

    # ---- around each stall -------------------------------------------
    for s, e, name in STALLS:
        print(f"\n================ {name}  {wall(s)} -> {wall(e)} ================")
        lo, hi = s - 45000, e + 15000
        bucket = defaultdict(int)
        for ts, d, p, pk in recs:
            if lo <= ts <= hi:
                proto, src, sp, dst, dp, extra = pk
                ep = dst if d == "t" else src
                bucket[(d, proto, ep, dp if d == "t" else sp)] += 1
        print("  flows in window:")
        for k in sorted(bucket, key=lambda k: -bucket[k])[:14]:
            print(f"    {k[0]} {k[1]:4s} {k[2]:>40s}:{k[3]:<6} n={bucket[k]}")
        print("  packet timeline (non-DNS):")
        n = 0
        for ts, d, p, pk in recs:
            if not (lo <= ts <= hi):
                continue
            if pk[5].startswith("DNS"):
                continue
            mark = ""
            if s <= ts <= e:
                mark = "  <<IN STALL>>"
            elif ts < s and s - ts <= 8000:
                mark = "  <<PRE>>"
            if mark or ts <= s:
                print(f"    {wall(ts)} {d} {pk[0]:4s} {pk[1]:>15s}:{pk[2]:<6} "
                      f"-> {pk[3]:>15s}:{pk[4]:<6} {pk[5]}{mark}")
                n += 1
            if n > 90:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
