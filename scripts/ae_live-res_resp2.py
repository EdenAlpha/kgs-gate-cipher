import csv, struct, collections
from reassemble import hms, safe

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
segs = collections.defaultdict(dict)
inbound_ports = collections.Counter()
for row in csv.reader(open(path, newline="", encoding="utf-8", errors="replace")):
    if not row or row[0].startswith("#") or row[0] == "ts_ms" or len(row) < 9: continue
    ts,d,proto,src,sport,dst,dport,iplen,hexs = row[:9]
    if proto != "tcp": continue
    inbound_ports[(d, int(sport), int(dport))] += 1
    if d != "r" or int(sport) != 80: continue
    pb = bytes.fromhex(hexs)
    ihl = (pb[0] & 0xF) * 4
    thl = (pb[ihl+12] >> 4) * 4
    if thl < 20: continue
    seq = struct.unpack_from(">I", pb, ihl+4)[0]
    pl = pb[ihl+thl:]
    if pl: segs[(src,sport,dst,dport)].setdefault(seq, (int(ts), pl))

print("inbound port-80 flows: %d" % len(segs))
for key, table in segs.items():
    buf = b"".join(table[s][1] for s in sorted(table))
    print("\n--- %s:%s -> %s:%s   %d bytes, ts %s" % (key[0],key[1],key[2],key[3],len(buf),hms(table[sorted(table)[0]][0])))
    print(safe(buf.decode("ascii","replace")))

print("\n\nrows by (dir,sport,dport) top 12:")
for k,v in inbound_ports.most_common(12): print("   ",k,v)
