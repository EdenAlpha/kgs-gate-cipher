import csv, collections

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"

def pr(b):
    return b.decode("ascii", "replace")

flows = collections.defaultdict(lambda: ([], []))   # (src,dport or sport) -> (payloads)
inbound = []
outbound = []

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
        try:
            pb = bytes.fromhex(hexs)
        except Exception:
            continue
        if len(pb) < 40:
            continue
        ihl = (pb[0] & 0xF) * 4
        thl = (pb[ihl + 12] >> 4) * 4
        pl = pb[ihl + thl:]
        if not pl:
            continue
        if int(sport) == 80:      # server -> phone
            inbound.append((int(ts), src, pl))
        elif int(dport) == 80:    # phone -> server
            outbound.append((int(ts), dst, pl))

print("=== inbound (server -> phone, sport 80): %d payloads ===" % len(inbound))
for ts, src, pl in inbound[:14]:
    print("  %s from %s len=%d" % (ts, src, len(pl)))
    print("     " + pr(pl[:500]))

print("\n=== outbound: reassembled request bodies ===")
for ts, dst, pl in outbound[:60]:
    if b"HTTP/1.1" in pl[:64]:
        he = pl.find(b"\r\n\r\n")
        print("  --- request ---")
        print("  " + pr(pl[:he]).replace("\r\n", "\n  "))
