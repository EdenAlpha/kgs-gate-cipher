import csv, re, collections, urllib.parse

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
T0 = 1790385845.048

bodies = []
with open(path, newline="") as f:
    rdr = csv.reader(f); hdr = None
    for row in rdr:
        if not row or row[0].startswith("#"):
            continue
        if hdr is None:
            hdr = row; continue
        ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
        if proto != "tcp" or int(dport) != 80:
            continue
        try:
            pb = bytes.fromhex(hexs)
        except Exception:
            continue
        ihl = (pb[0] & 0xF) * 4
        thl = (pb[ihl + 12] >> 4) * 4
        pl = pb[ihl + thl:]
        if b"ReportLog.php HTTP/1.1" not in pl:
            continue
        he = pl.find(b"\r\n\r\n")
        if he < 0:
            continue
        bodies.append((int(ts), pl[he + 4:]))

print("ReportLog bodies: %d\n" % len(bodies))
KW = ("abnormal", "disconnect", "disconnet", "timeout", "watchdog", "stun",
      "giveup", "give_up", "forfeit", "network", "background", "strange",
      "reason", "close", "peer", "keepalive", "error", "fail")

for idx, (ts, b) in enumerate(bodies):
    txt = b.decode("ascii", "replace")
    off = ts / 1000.0 - T0
    dat = None
    if "dat=" in txt:
        dat = txt.split("dat=", 1)[1]
        try:
            dat = urllib.parse.unquote(dat)
        except Exception:
            pass
        try:
            dat = bytes.fromhex(dat).decode("utf-8", "replace")
        except Exception:
            dat = None
    print("=" * 70)
    print("body %d   at session %02d:%05.2f   outer=%d chars"
          % (idx, off // 60, off % 60, len(txt)))
    if dat:
        print("decoded dat length: %d" % len(dat))
        print("--- first 700 chars ---")
        print(dat[:700])
        hits = sorted({k for k in KW if k in dat.lower()})
        print("--- keyword hits: %s" % (hits or "none"))
        for k in hits:
            m = re.search(k, dat, re.I)
            if m:
                s = max(0, m.start() - 70)
                print("      %s ... %s ..." % (k, dat[s:m.start() + 110].replace("\n", " | ")))
    if idx >= 2:
        print("\n(only first 3 bodies printed in full)")
        break
