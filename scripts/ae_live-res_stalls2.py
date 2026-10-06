import csv, datetime
p = r"captures\match-2026-09-26\z1-tiamant-client\udp_trace.csv"
rel = []
with open(p, newline="", encoding="utf-8", errors="replace") as f:
    rdr = csv.reader(f)
    hdr = None
    for row in rdr:
        if not row or row[0].startswith("#"): continue
        if hdr is None:
            hdr = row; continue
        try: rel.append(float(row[9]))
        except Exception: pass
rel.sort()
print("packets:", len(rel), "span: %.1f s" % (rel[-1]/1000.0))
gaps=[]
prev=rel[0]
for t in rel[1:]:
    if t-prev > 3000: gaps.append((prev,t,t-prev))
    prev=t
print("\ngaps > 3 s in game stream:")
for a,b,g in gaps:
    print("   rel %9.1f -> %9.1f   gap %7.1f s" % (a/1000.0,b/1000.0,g/1000.0))
# now correlate with pass-through event markers
p2 = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
print("\n--- passthrough rows that are NOT packets (event markers) ---")
n=0
with open(p2, newline="", encoding="utf-8", errors="replace") as f:
    rdr=csv.reader(f)
    hdr=None
    for row in rdr:
        if not row: continue
        if row[0].startswith("#"): print("  COMMENT:", row[0][:200]); continue
        if hdr is None:
            hdr=row; print("  HEADER:", row); continue
        if len(row)<9 or not row[8] or len(row[8])<8:
            print("  ODD:", row[:12])
            n+=1
            if n>25: break
