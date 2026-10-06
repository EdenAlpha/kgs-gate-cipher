import csv, struct, collections, re

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
flows = collections.defaultdict(list)
for row in csv.reader(open(path, newline="", encoding="utf-8", errors="replace")):
    if not row or row[0].startswith("#") or row[0] == "ts_ms" or len(row) < 9:
        continue
    ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
    if proto != "tcp" or d != "t" or int(dport) != 80:
        continue
    try:
        pb = bytes.fromhex(hexs)
    except Exception:
        continue
    ihl = (pb[0] & 0xF) * 4
    thl = (pb[ihl + 12] >> 4) * 4
    if thl < 20:
        continue
    seq = struct.unpack_from(">I", pb, ihl + 4)[0]
    flags = pb[ihl + 13]
    pl = pb[ihl + thl:]
    flows[(src, sport, dst, dport)].append((int(ts), seq, flags, len(pl), int(iplen), len(pb)))

print("outbound port-80 flows: %d\n" % len(flows))
for key, segs in sorted(flows.items()):
    segs.sort()
    payload = [s for s in segs if s[3] > 0]
    if not payload:
        continue
    lo = min(s[1] for s in payload)
    hi = max(s[1] + s[3] for s in payload)
    total_payload = sum(s[3] for s in payload)
    # coverage of [lo, hi)
    cov = set()
    for _, seq, fl, n, ipl, raw in payload:
        for i in range(seq, seq + n):
            cov.add(i)
    print("flow %s:%s" % (key[0], key[1]))
    print("   segments=%d  with_payload=%d" % (len(segs), len(payload)))
    print("   seq span      = %d  (0x%x .. 0x%x)" % (hi - lo, lo, hi))
    print("   sum(payload)  = %d" % total_payload)
    print("   unique bytes  = %d   MISSING=%d" % (len(cov), (hi - lo) - len(cov)))
    # check first segment size vs ip_len
    s0 = payload[0]
    print("   first: raw_ip=%d ip_len_field=%d payload=%d flags=0x%02x" % (s0[5], s0[4], s0[3], s0[2]))
    # HTTP Content-Length if present
    buf = b"".join(bytes.fromhex(r[8]) for r in
                   [row for row in [] ]) if False else None
    print()

