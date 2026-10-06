import csv, io, collections
p = r"captures\match-2026-09-26\z1-tiamant-client\udp_trace.csv"
ts = []
with open(p, newline="", encoding="utf-8", errors="replace") as f:
    hdr = None
    for row in csv.reader(f):
        if not row: continue
        if hdr is None:
            hdr = row
            print("HEADER:", row)
            continue
        try:
            ts.append(int(float(row[0])))
        except Exception:
            pass
print("rows:", len(ts), "first", ts[0], "last", ts[-1])
base = ts[0]
ts.sort()
# detect gaps
gaps = []
prev = ts[0]
for t in ts[1:]:
    if t - prev > 5000:
        gaps.append((prev, t, t - prev))
    prev = t
print("\ngaps > 5 s:")
for a, b, g in gaps:
    print("   %.1f -> %.1f   (%.1f s)" % ((a-base)/1000.0, (b-base)/1000.0, g/1000.0))
