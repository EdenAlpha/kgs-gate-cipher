import csv, re, collections, urllib.parse

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
s80 = collections.Counter()
bodies = []

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
        s80[(d, int(sport), int(dport))] += 1
        try:
            pb = bytes.fromhex(hexs)
        except Exception:
            continue
        if len(pb) < 40:
            continue
        ihl = (pb[0] & 0xF) * 4
        thl = (pb[ihl + 12] >> 4) * 4
        pl = pb[ihl + thl:]
        if int(dport) == 80 and b"ReportLog.php HTTP/1.1" in pl:
            he = pl.find(b"\r\n\r\n")
            if he > 0:
                bodies.append(pl[he + 4:])

print("=== rows involving port 80 ===")
for k, v in s80.most_common(12):
    print("   dir=%s sport=%d dport=%d  %d" % (k[0], k[1], k[2], v))

print("\n=== decoded ReportLog bodies: %d ===" % len(bodies))
KW = ("abnormal", "disconnect", "timeout", "watchdog", "stun", "giveup",
      "give_up", "forfeit", "network", "background", "strange", "reason")
for i, b in enumerate(bodies):
    txt = b.decode("ascii", "replace")
    # body is urlencoded hex: req=<hex>
    decoded = txt
    if "req=" in txt:
        try:
            decoded = urllib.parse.unquote(txt.replace("req=", "", 1))
        except Exception:
            pass
    if i == 0:
        print("\n--- body %d (first 900 chars after hex-decode) ---" % i)
        print(decoded[:900])
    hits = [k for k in KW if k in decoded.lower()]
    if hits:
        print("\n--- body %d  MATCHED %s ---" % (i, hits))
        for k in hits:
            for m in re.finditer(k, decoded, re.I):
                s = max(0, m.start() - 90)
                print("      ..." + decoded[s:m.start() + 130].replace("\n", " | ") + "...")
                break
