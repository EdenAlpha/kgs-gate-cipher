"""score_host.py -- which host carries the full-time result?

Ties score_channel.py's port-443 observation to a name, two ways:
  A. TLS SNI from every ClientHello in both captures (with timestamps)
  B. every DNS A-record answer, so destination IPs can be resolved
  C. for the +-45 s score_commit window: destination IP -> resolved name,
     so we can say exactly which host the result rode on.

Self-contained: deliberately does NOT import cap_sni (that file executes its
own report on import) and forces ASCII-safe printing.
"""
import csv
import collections
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PHONES = [r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv",
          r"captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"]

SCORE = 1790387785479
T0 = 1790385845.048
WIN = 45


def hhmmss(ms):
    off = (ms - T0 * 1000.0) / 1000.0
    return "%02d:%06.3f" % (off // 60, off % 60)


def split_ip(hx):
    b = bytes.fromhex(hx)
    if not b or b[0] >> 4 != 4:
        return None
    ihl = (b[0] & 0xF) * 4
    proto = b[9]
    total = int.from_bytes(b[2:4], "big")
    body = b[ihl:total] if total <= len(b) else b[ihl:]
    if proto == 6 and len(body) >= 20:
        sp = int.from_bytes(body[0:2], "big")
        dp = int.from_bytes(body[2:4], "big")
        doff = (body[12] >> 4) * 4
        flags = body[13]
        return "tcp", sp, dp, flags, body[doff:]
    if proto == 17 and len(body) >= 8:
        sp = int.from_bytes(body[0:2], "big")
        dp = int.from_bytes(body[2:4], "big")
        return "udp", sp, dp, None, body[8:]
    return None


def sni_of(rec):
    """Strict TLS 1.2/1.3 ClientHello -> server_name. Returns None if unsure."""
    try:
        if len(rec) < 45 or rec[0] != 0x16:
            return None
        if rec[1] != 0x03:
            return None
        rec_len = int.from_bytes(rec[3:5], "big")
        p = rec[5:5 + rec_len]
        if len(p) < 40 or p[0] != 0x01:
            return None
        q = 4 + 2 + 32                       # hs hdr + client version + random
        if q >= len(p):
            return None
        sidlen = p[q]
        q += 1 + sidlen
        if q + 2 > len(p):
            return None
        cslen = int.from_bytes(p[q:q + 2], "big")
        q += 2 + cslen
        if q + 1 > len(p):
            return None
        complen = p[q]
        q += 1 + complen
        if q + 2 > len(p):
            return None
        extlen = int.from_bytes(p[q:q + 2], "big")
        q += 2
        end = min(q + extlen, len(p))
        while q + 4 <= end:
            et = int.from_bytes(p[q:q + 2], "big")
            el = int.from_bytes(p[q + 2:q + 4], "big")
            q += 4
            if q + el > end:
                break
            if et == 0 and el >= 5:
                ntype = p[q]
                if ntype != 0:
                    return None
                nl = int.from_bytes(p[q + 3:q + 5], "big")
                name = p[q + 5:q + 5 + nl]
                if len(name) == nl and all(32 <= c < 127 for c in name):
                    return name.decode("ascii")
                return None
            q += el
    except Exception:
        return None
    return None


def read_name(buf, i, depth=0):
    out = []
    seen = set()
    while i < len(buf):
        if i in seen or depth > 20:
            break
        seen.add(i)
        l = buf[i]
        if l == 0:
            i += 1
            break
        if l & 0xC0 == 0xC0:
            if i + 1 >= len(buf):
                break
            ptr = ((l & 0x3F) << 8) | buf[i + 1]
            sub, _ = read_name(buf, ptr, depth + 1)
            out.append(sub)
            i += 2
            break
        i += 1
        out.append(buf[i:i + l].decode("ascii", "replace"))
        i += l
    return ".".join(x for x in out if x), i


def dns_answers(payload):
    out = []
    try:
        if len(payload) < 12:
            return out
        qd, an = struct.unpack("!HH", payload[4:8])
        if an == 0:
            return out
        p = 12
        for _ in range(qd):
            _, p = read_name(payload, p)
            p += 4
        for _ in range(an):
            _, p = read_name(payload, p)
            if p + 10 > len(payload):
                break
            typ, cls, ttl, rdlen = struct.unpack("!HHIH", payload[p:p + 10])
            p += 10
            rdata = payload[p:p + rdlen]
            p += rdlen
            if typ == 1 and rdlen == 4:
                out.append((".".join(str(x) for x in rdata),))
    except Exception:
        pass
    return out


def dns_qname(payload):
    try:
        if len(payload) < 12:
            return None
        n, _ = read_name(payload, 12)
        return n or None
    except Exception:
        return None


print("=" * 78)
print("A. every TLS ClientHello SNI seen, both phones")
print("=" * 78)
ip_sni = collections.defaultdict(set)
sni_seen = collections.Counter()
for path in PHONES:
    tag = path.split("\\")[-2]
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        next(rd)
        for row in rd:
            if len(row) < 9 or row[2] != "tcp" or row[1] != "t":
                continue
            f = split_ip(row[8])
            if not f or f[0] != "tcp" or not f[4]:
                continue
            host = sni_of(f[4])
            if host:
                ip_sni[row[5]].add(host)
                sni_seen[host] += 1
                print("  %-46s %s  (%s) -> %s"
                      % (host, hhmmss(int(row[0])), tag, row[5]))

print()
print("=" * 78)
print("B. DNS: names queried, and A-record answers")
print("=" * 78)
ip_name = collections.defaultdict(set)
name_ip = collections.defaultdict(set)
queries = collections.Counter()
for path in PHONES:
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        next(rd)
        for row in rd:
            if len(row) < 9 or row[2] != "udp":
                continue
            f = split_ip(row[8])
            if not f or f[0] != "udp" or not f[4]:
                continue
            if row[6] == "53":
                qn = dns_qname(f[4])
                if qn:
                    queries[qn] += 1
            if row[4] == 53:
                for (ip,) in dns_answers(f[4]):
                    qn = dns_qname(f[4])
                    ip_name[ip].add(qn)
                    name_ip[qn].add(ip)

print("\n  names queried (top):")
for nm, n in queries.most_common(25):
    print("    %-50s x%d" % (nm, n))

print("\n  A-record answers for konami / pes hosts:")
for nm in sorted(n for n in name_ip if n and ("konami" in n or "pes" in n.lower())):
    print("    %-50s %s" % (nm, ", ".join(sorted(name_ip[nm]))))

print("\n  -- resolve the destinations seen at score_commit (see C) --")

print()
print("=" * 78)
print("C. score_commit window +-%.0fs: outbound TCP by destination" % WIN)
print("=" * 78)
window_dests = {}
for path in PHONES:
    tag = path.split("\\")[-2]
    print("\n--- %s" % tag)
    dests = collections.Counter()
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        next(rd)
        for row in rd:
            if len(row) < 9 or row[1] != "t":
                continue
            ts = int(row[0])
            if not (SCORE - WIN * 1000 <= ts <= SCORE + WIN * 1000):
                continue
            f = split_ip(row[8])
            if not f or f[0] != "tcp":
                continue
            if f[4]:
                dests[(row[5], f[2])] += len(f[4])
    window_dests[tag] = dests
    if not dests:
        print("   no outbound TCP payload in window")
    for (ip, port), n in sorted(dests.items(), key=lambda kv: -kv[1]):
        names = sorted(x for x in (ip_name.get(ip, set()) | ip_sni.get(ip, set())) if x)
        print("   %-18s :%-6d %7d bytes   %s"
              % (ip, port, n, ", ".join(names) if names else "(unresolved)"))

print()
print("=" * 78)
print("D. port 80 vs port 443 in the same window")
print("=" * 78)
for tag, dests in window_dests.items():
    p80 = sum(n for (ip, port), n in dests.items() if port == 80)
    p443 = sum(n for (ip, port), n in dests.items() if port == 443)
    other = sum(dests.values()) - p80 - p443
    print("  %-26s port80=%d  port443=%d  other=%d"
          % (tag, p80, p443, other))

print()
print("=" * 78)
print("E. whole capture: port 80 vs 443 outbound payload bytes")
print("=" * 78)
for path in PHONES:
    tag = path.split("\\")[-2]
    tot = collections.Counter()
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        next(rd)
        for row in rd:
            if len(row) < 9 or row[1] != "t":
                continue
            f = split_ip(row[8])
            if not f or f[0] != "tcp" or not f[4]:
                continue
            tot[f[2]] += len(f[4])
    print("  %-26s  :80=%d   :443=%d   other=%d"
          % (tag, tot.get(80, 0), tot.get(443, 0),
             sum(v for k, v in tot.items() if k not in (80, 443))))
