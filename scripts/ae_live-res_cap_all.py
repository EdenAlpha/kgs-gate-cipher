import csv, re, glob, collections, os

files = sorted(glob.glob(r"captures\**\passthrough_capture.csv", recursive=True))
print("captures found: %d" % len(files))
for path in files:
    reqs = collections.Counter()
    hosts = collections.Counter()
    ports = collections.Counter()
    tmin = tmax = None
    with open(path, newline="") as f:
        rdr = csv.reader(f); hdr = None
        for row in rdr:
            if not row or row[0].startswith("#"):
                continue
            if hdr is None:
                hdr = row; continue
            ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
            t = int(ts)
            tmin = t if tmin is None else min(tmin, t)
            tmax = t if tmax is None else max(tmax, t)
            if proto == "tcp":
                ports[int(dport)] += 1
                if int(dport) == 80:
                    try:
                        pb = bytes.fromhex(hexs)
                    except Exception:
                        continue
                    ihl = (pb[0] & 0xF) * 4
                    thl = (pb[ihl + 12] >> 4) * 4
                    pl = pb[ihl + thl:]
                    m = re.match(rb"(GET|POST) (\S+) HTTP", pl)
                    if m:
                        reqs[(m.group(1).decode(), m.group(2).decode())] += 1
                        hm = re.search(rb"Host: ([^\r\n]+)", pl)
                        if hm:
                            hosts[hm.group(1).decode()] += 1
    span = (tmax - tmin) / 1000.0 if tmin else 0
    print("\n%s" % path)
    print("   window: %.1f s   (tcp dport 443=%d, dport 80=%d, udp=%d)"
          % (span, ports.get(443, 0), ports.get(80, 0),
             sum(v for k, v in ports.items() if k not in (80, 443))))
    print("   PLAINTEXT HTTP hosts: %s" % (dict(hosts) or "NONE"))
    for k, v in reqs.most_common(20):
        print("      %-6s %-45s x%d" % (k[0], k[1], v))
    if not reqs:
        print("      (no plaintext HTTP requests at all)")
