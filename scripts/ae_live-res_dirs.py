import csv, collections
c = collections.Counter()
for f in [r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv",
          r"captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"]:
    k = collections.Counter()
    for row in csv.reader(open(f, newline="", encoding="utf-8", errors="replace")):
        if not row or row[0].startswith("#") or row[0] == "ts_ms" or len(row) < 9: continue
        k[(row[1], row[2])] += 1
    print(f.split("\\")[-2])
    for key in sorted(k): print("    dir=%s proto=%-5s %d" % (key[0], key[1], k[key]))
    print("    TOTAL rows:", sum(k.values()))
