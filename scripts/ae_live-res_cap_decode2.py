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
        try:
            pb = bytes.fromhex(hexs)
        except Exception:
            continue
        ihl = (pb[0] & 0xF) * 4
        thl = (pb[ihl + 12] >> 4) * 4
        pl = pb[ihl + thl:]
        if not pl:
            continue
        flows[(src, sport, dst, dport, d)].append((int(ts), pl))

messages = []
for key, segs in flows.items():
    segs.sort()
    if int(key[3]) != 80 or key[4] != "t":
        continue
    buf = b"".join(s for _, s in segs)
    # split into HTTP requests using Content-Length
    i = 0
    while True:
        m = re.search(rb"POST (\S+) HTTP/1\.[01]\r\n", buf[i:])
        if not m:
            break
        start = i + m.start()
        hend = buf.find(b"\r\n\r\n", start)
        if hend < 0:
            break
        hdrs = buf[start:hend]
        cl = re.search(rb"Content-Length: (\d+)", hdrs)
        n = int(cl.group(1)) if cl else 0
        body = buf[hend + 4:hend + 4 + n]
        t = segs[0][0]
        messages.append((t, m.group(1).decode(), hdrs, body))
        i = hend + 4 + n

print("reassembled HTTP messages: %d\n" % len(messages))
def safe(s):
    return s.encode("ascii", "replace").decode("ascii")
KW = ("abnormal", "disconnect", "disconnet", "timeout", "watchdog", "stun",
      "giveup", "give_up", "forfeit", "network", "background", "strange",
      "reason", "close", "peer", "keepalive", "error", "fail", "match")

for idx, (t, path_s, hdrs, body) in enumerate(messages):
    off = t / 1000.0 - T0
    print("=" * 74)
    print("#%d  %s  at session %02d:%05.2f  body=%d bytes"
          % (idx, path_s, off // 60, off % 60, len(body)))
    txt = body.decode("ascii", "replace")
    dat = None
    if "dat=" in txt:
        raw = txt.split("dat=", 1)[1]
        raw = urllib.parse.unquote(raw)
        try:
            dat = bytes.fromhex(raw).decode("utf-8", "replace")
        except Exception as e:
            dat = "<hex decode failed: %s>" % e
    if dat:
        print("--- decoded NTLInfo (%d chars), first 800 ---" % len(dat))
        print(safe(dat[:800]))
        hits = sorted({k for k in KW if k in dat.lower()})
        print("--- keyword hits: %s" % (hits or "NONE"))
        for k in hits[:8]:
            m2 = re.search(k, dat, re.I)
            s = max(0, m2.start() - 80)
            print("    %-12s ... %s ..." % (k, safe(dat[s:m2.start() + 140].replace(chr(10), " | "))))
    if idx >= 1:
        print("\n(remaining bodies scanned for keywords only)")
        break

# keyword scan over ALL decoded bodies
print("\n" + "=" * 74)
print("KEYWORD SCAN OVER ALL %d MESSAGES" % len(messages))
tot = collections.Counter()
for idx, (t, path_s, hdrs, body) in enumerate(messages):
    txt = body.decode("ascii", "replace")
    if "dat=" not in txt:
        continue
    raw = urllib.parse.unquote(txt.split("dat=", 1)[1])
    try:
        dat = bytes.fromhex(raw).decode("utf-8", "replace")
    except Exception:
        continue
    hits = [k for k in KW if k in dat.lower()]
    for k in hits:
        tot[k] += 1
    if hits:
        print("  msg #%d (%s): %s" % (idx, path_s, hits))
print("totals:", dict(tot))
