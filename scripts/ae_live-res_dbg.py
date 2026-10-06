import csv, re, collections, urllib.parse
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
print("flows:", len(flows))
n80 = [k for k in flows if int(k[3])==80 and k[4]=="t"]
print("outbound-80 flows:", len(n80))
msgs=[]
for key, segs in flows.items():
    if int(key[3]) != 80 or key[4] != "t": continue
    segs.sort()
    buf = b"".join(s for _, s in segs)
    i = 0
    while True:
        m = re.search(rb"POST (\S+) HTTP/1\.[01]\r\n", buf[i:])
        if not m: break
        start = i + m.start()
        hend = buf.find(b"\r\n\r\n", start)
        if hend < 0: break
        cl = re.search(rb"Content-Length: (\d+)", buf[hend:])
        n = int(cl.group(1)) if cl else 0
        msgs.append((segs[0][0], m.group(1).decode(), buf[hend+4:hend+4+n]))
        i = hend + 4 + n
print("msgs:", len(msgs))
for t,p,b in msgs[:3]:
    txt=b.decode("ascii","replace")
    print(" ", p, len(b), "has dat=" , "dat=" in txt)
    if "dat=" in txt:
        raw = urllib.parse.unquote(txt.split("dat=",1)[1])
        try:
            dat = bytes.fromhex(raw).decode("utf-8","replace")
            print("    dat chars:", len(dat), "lines:", len(dat.splitlines()))
            for ln in dat.splitlines():
                low=ln.lower()
                if "timeout" in low or "peer" in low or "close" in low:
                    print("      HIT:", ln.strip()[:160].encode("ascii","replace").decode())
        except Exception as e:
            print("    decode fail", e)
