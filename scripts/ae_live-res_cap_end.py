import csv, socket, struct, collections, datetime

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"

# session start: log 02:24:05.048 <-> epoch 1790385845.048
T0 = 1790385845.048
def logtime(ms):
    return datetime.datetime.fromtimestamp(ms / 1000.0) - datetime.datetime.fromtimestamp(T0)

def hms(sec):
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    return "%02d:%02d:%02d" % (h, m, s)

# 02:56:25.478 minus 02:24:05.048 = 1940.43 s  (both are 02:xx, so 2*3600 base)
MATCH_END = 1790385845.048 + ((2 * 3600 + 56 * 60 + 25.478) - (2 * 3600 + 24 * 60 + 5.048))
print("match end epoch = %.3f  (= session + %.1f s)" % (MATCH_END, MATCH_END - T0))

flow = collections.defaultdict(lambda: [None, None, 0])
events = []
import re
pl_requests = []
with open(path, newline="") as f:
    rdr = csv.reader(f); hdr = None
    for row in rdr:
        if not row or row[0].startswith("#"):
            continue
        if hdr is None:
            hdr = row; continue
        ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
        if proto != "tcp":
            continue
        t = int(ts)
        if int(dport) in (80, 443):
            k = (dst, int(dport))
            st = flow[k]
            st[0] = t if st[0] is None else min(st[0], t)
            st[1] = t if st[1] is None else max(st[1], t)
            st[2] += 1
            if abs(t - MATCH_END * 1000.0) < 60000:
                events.append((t, dst, int(dport), d))
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
                pl_requests.append((t, m.group(2).decode()))

print("\n=== EVERY plaintext HTTP request, session-relative ===")
for t, p in pl_requests:
    off = t / 1000.0 - T0
    mark = "  <== MATCH END" if abs(t - MATCH_END * 1000.0) < 60000 else ""
    print("   %s  %s%s" % (hms(off) if False else "%02d:%06.3f" % (off // 60, off % 60), p, mark))

print("\\n=== flows active within 60s of match end ===")
for t, dst, dp, direction in sorted(events):
    tag = "PLAINTEXT" if dp == 80 else "TLS"
    print("   +%6.1fs  -> %-18s :%-5d %-9s %s" % (t / 1000.0 - T0, dst, dp, tag, direction))

print("\n=== per-flow lifetime (session-relative) ===")
for (dst, dp), (a, b, n) in sorted(flow.items(), key=lambda x: -(x[1][2])):
    if n < 3:
        continue
    print("   %-18s :%-5d %s -> %s  (%d pkts)"
          % (dst, dp, hms(a / 1000.0 - T0), hms(b / 1000.0 - T0), n))


