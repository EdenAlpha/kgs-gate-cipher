import csv, socket, struct, collections

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"

def read_name(b, i, depth=0):
    out = []
    if depth > 8:
        return "", i
    while i < len(b):
        l = b[i]
        if l == 0:
            i += 1; break
        if l & 0xC0 == 0xC0:
            ptr = ((l & 0x3F) << 8) | b[i + 1]
            n, _ = read_name(b, ptr, depth + 1)
            out.append(n); i += 2; break
        i += 1
        out.append(b[i:i + l].decode("latin-1", "replace")); i += l
    return ".".join(out), i

a_records = collections.defaultdict(set)
tcp_payload = collections.Counter()          # (ip, dport) -> pkts with payload
http_req = collections.Counter()             # (ip, path)

with open(path, newline="") as f:
    rdr = csv.reader(f); hdr = None
    for row in rdr:
        if not row or row[0].startswith("#"):
            continue
        if hdr is None:
            hdr = row; continue
        ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
        try:
            pb = bytes.fromhex(hexs)
        except Exception:
            continue
        # DNS RESPONSES leave the server on port 53
        if proto == "udp" and int(sport) == 53 and len(pb) >= 40:
            dns = pb[28:]
            if len(dns) < 12:
                continue
            qd, an = struct.unpack("!HH", dns[4:8])
            i = 12
            for _ in range(qd):
                _, i = read_name(dns, i); i += 4
            for _ in range(an):
                nm, i = read_name(dns, i)
                typ, cls, ttl, rdlen = struct.unpack("!HHIH", dns[i:i + 10]); i += 10
                rd = dns[i:i + rdlen]; i += rdlen
                if typ == 1 and rdlen == 4:
                    a_records[nm].add(socket.inet_ntoa(rd))
        elif proto == "tcp" and int(dport) in (80, 443):
            ihl = (pb[0] & 0xF) * 4
            thl = (pb[ihl + 12] >> 4) * 4
            pl = pb[ihl + thl:]
            if pl:
                tcp_payload[(dst, int(dport))] += 1
                if int(dport) == 80:
                    import re
                    m = re.match(rb"(GET|POST) (\S+)", pl)
                    if m:
                        http_req[(dst, m.group(2).decode())] += 1

ip2host = {}
for nm, ips in a_records.items():
    for ip in ips:
        ip2host.setdefault(ip, set()).add(nm)

print("=== DNS A records captured (%d names) ===" % len(a_records))
for nm in sorted(a_records):
    print("   %-46s -> %s" % (nm, sorted(a_records[nm])))

print("\n=== TCP servers with payload ===")
for (ip, dp), n in sorted(tcp_payload.items(), key=lambda x: -x[1]):
    hosts = sorted(ip2host.get(ip, []))
    proto = "PLAINTEXT HTTP" if dp == 80 else "TLS (encrypted)"
    print("   %-18s :%-5d %-16s %5d pkts  %s" % (ip, dp, proto, n, hosts or "(no DNS seen)"))

print("\n=== plaintext HTTP endpoints ===")
for (ip, p), n in http_req.most_common():
    print("   %-18s %-45s x%d" % (ip, p, n))
