import csv, struct, collections
path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
want = "43718"
rows = []
for row in csv.reader(open(path, newline="", encoding="utf-8", errors="replace")):
    if not row or row[0].startswith("#") or row[0] == "ts_ms" or len(row) < 9: continue
    ts,d,proto,src,sport,dst,dport,iplen,hexs = row[:9]
    if proto!="tcp" or d!="t" or sport!=want: continue
    pb = bytes.fromhex(hexs)
    ver = pb[0] >> 4
    ihl = (pb[0] & 0xF) * 4
    thl = (pb[ihl+12] >> 4) * 4
    seq = struct.unpack_from("<I", pb, ihl+4)[0]
    flags = pb[ihl+13]
    pl = pb[ihl+thl:]
    rows.append((int(ts), ver, ihl, thl, seq, flags, len(pl), pb[:20].hex()))
for r in sorted(rows):
    print("ts=%d ver=%d ihl=%d thl=%d seq=%d(0x%x) flags=0x%02x plen=%d head=%s" % (r[0],r[1],r[2],r[3],r[4],r[4],r[5],r[6],r[7]))
