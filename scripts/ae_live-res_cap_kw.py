import csv, re, collections, urllib.parse

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
T0 = 1790385845.048
flows = collections.defaultdict(list)

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
        pb = bytes.fromhex(hexs)
        ihl = (pb[0] & 0xF) * 4
        thl = (pb[ihl + 12] >> 4) * 4
        pl = pb[ihl + thl:]
        if pl:
            flows[(src, sport, dst, dport, d)].append((int(ts), pl))

msgs = []
for key, segs in flows.items():
    if int(key[3]) != 80 or key[4] != "t":
        continue
    segs.sort()
    buf = b"".join(s for _, s in segs)
    i = 0
    while True:
        m = re.search(rb"POST (\S+) HTTP/1\.[01]\r\n", buf[i:])
        if not m:
            break
        start = i + m.start()
        hend = buf.find(b"\r\n\r\n", start)
        if hend < 0:
            break
        cl = re.search(rb"Content-Length: (\d+)", buf[start:hend])
        n = int(cl.group(1)) if cl else 0
        body = buf[hend + 4:hend + 4 + n]
        msgs.append((segs[0][0], m.group(1).decode(), body))
        i = hend + 4 + n

def safe(s):
    return s.encode("ascii", "replace").decode("ascii")

msgs.sort()
TARGETS = ["timeout", "peer", "close", "keepalive", "abnormal", "disconnect"]
for t, p, body in msgs:
    if p == "/ntl/api/GateInfo.php":
        continue
    txt = body.decode("ascii", "replace")
    if "dat=" not in txt:
        continue
    raw = urllib.parse.unquote(txt.split("dat=", 1)[1])
    try:
        dat = bytes.fromhex(raw).decode("utf-8", "replace")
    except Exception:
        continue
    off = t / 1000.0 - T0
    lines = dat.splitlines()
    found = []
    for ln in lines:
        low = ln.lower()
        for k in TARGETS:
            if k in low:
                found.append((k, ln.strip()))
                break
    if found:
        print("=" * 76)
        print("session %02d:%05.2f  %s   (%d lines total)" % (off // 60, off % 60, p, len(lines)))
        seen = set()
        for k, ln in found[:14]:
            key = (k, ln[:110])
            if key in seen:
                continue
            seen.add(key)
            print("   [%-11s] %s" % (k, safe(ln[:190])))
