import csv, re, collections
path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
flows = collections.defaultdict(list)
with open(path, newline="") as f:
    rdr = csv.reader(f); hdr = None
    for row in rdr:
        if not row or row[0].startswith("#"): continue
        if hdr is None: hdr = row; continue
        ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
        if proto != "tcp": continue
        try: pb = bytes.fromhex(hexs)
        except Exception: continue
        ihl = (pb[0] & 0xF) * 4
        thl = (pb[ihl + 12] >> 4) * 4
        pl = pb[ihl + thl:]
        if pl: flows[(src, sport, dst, dport, d)].append((int(ts), pl))
for key, segs in flows.items():
    if int(key[3]) != 80 or key[4] != "t": continue
    segs.sort()
    buf = b"".join(s for _, s in segs)
    print("flow", key, "buf len", len(buf), "segs", len(segs))
    i = 0
    while True:
        m = re.search(rb"POST (\S+) HTTP/1\.[01]\r\n", buf[i:])
        if not m: break
        start = i + m.start()
        hend = buf.find(b"\r\n\r\n", start)
        print("   ", m.group(1), "start", start, "hend", hend, "buflen", len(buf))
        cl = re.search(rb"Content-Length: (\d+)", buf[hend:hend+400])
        print("      cl match:", cl.group(1) if cl else None)
        n = int(cl.group(1)) if cl else 0
        i = hend + 4 + n
        if n == 0: break
