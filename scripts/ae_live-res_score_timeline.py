"""score_timeline.py -- per-second view of both channels either side of
score_commit, so the result burst and any plaintext report can be told apart.
"""
import csv
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PHONES = [r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv",
          r"captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"]

SCORE = 1790387785479
T0 = 1790385845.048
LO, HI = SCORE - 90 * 1000, SCORE + 60 * 1000


def hhmmss(ms):
    off = (ms - T0 * 1000.0) / 1000.0
    return "%02d:%06.3f" % (off // 60, off % 60)


def payload_of(hx):
    b = bytes.fromhex(hx)
    if not b or b[0] >> 4 != 4:
        return None, None, b
    ihl = (b[0] & 0xF) * 4
    proto = b[9]
    total = int.from_bytes(b[2:4], "big")
    body = b[ihl:total] if total <= len(b) else b[ihl:]
    if proto == 6 and len(body) >= 20:
        doff = (body[12] >> 4) * 4
        return "tcp", int.from_bytes(body[2:4], "big"), body[doff:]
    if proto == 17 and len(body) >= 8:
        return "udp", int.from_bytes(body[2:4], "big"), body[8:]
    return "udp", None, body


for path in PHONES:
    tag = path.split("\\")[-2]
    print("=" * 78)
    print(tag)
    print("=" * 78)
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        next(rd)
        for row in rd:
            if len(row) < 9 or row[1] != "t":
                continue
            ts = int(row[0])
            if not (LO <= ts <= HI):
                continue
            proto, dp, pay = payload_of(row[8])
            if proto != "tcp" or not pay:
                continue
            rows.append((ts, dp, pay))

    # second buckets, split by port
    buckets = {}
    for ts, dp, pay in rows:
        k = (ts // 1000, dp)
        buckets[k] = buckets.get(k, 0) + len(pay)

    print("\n  outbound TCP payload bytes/second (port 80 = plaintext)")
    print("  %-14s %10s %10s %10s" % ("time", "port 80", "port 443", "other"))
    secs = sorted({k[0] for k in buckets})
    for s in secs:
        a = buckets.get((s, 80), 0)
        b = buckets.get((s, 443), 0)
        c = sum(v for (ss, p), v in buckets.items() if ss == s and p not in (80, 443))
        if not (a or b or c):
            continue
        mark = ""
        if s * 1000 <= SCORE < (s + 1) * 1000:
            mark = "   <<< score_commit"
        print("  %-14s %10d %10d %10d%s"
              % (hhmmss(s * 1000), a, b, c, mark))

    print("\n  every outbound plaintext HTTP request line in the window:")
    n = 0
    for ts, dp, pay in rows:
        i = pay.find(b"HTTP/1.1")
        if i < 0:
            continue
        line = pay[:i + 8]
        if line.startswith(b"GET ") or line.startswith(b"POST "):
            n += 1
            print("    %s  %s" % (hhmmss(ts), line.decode("ascii", "replace")))
    if n == 0:
        print("    (none)")
    print()
