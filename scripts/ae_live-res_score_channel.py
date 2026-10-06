"""score_channel.py -- does the full-time result go over HTTP or HTTPS?

Three independent tests against both phones' full-byte capture:
  1. search EVERY payload byte for all 330 .php endpoint names known to
     libUE4.so (plus 'Cmd' fragments) -> which ones ever appear in the clear
  2. list every plaintext HTTP request line seen on port 80
  3. what actually happened on the wire +-45 s around score_commit
"""

import csv
import re
import sys
import collections

PHONES = [r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv",
          r"captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"]

SCORE = 1790387785479
T0 = 1790385845.048
WIN = 45

STRDUMP = r"efootball-apk\ue4_strings.txt"
s = open(STRDUMP, encoding="utf-8", errors="replace").read()
ENDPOINTS = sorted(set(re.findall(r"\b[A-Za-z][A-Za-z0-9_]{2,40}\.php\b", s)))


def hhmmss(ms):
    off = (ms - T0 * 1000.0) / 1000.0
    return "%02d:%06.3f" % (off // 60, off % 60)


def parse_pkt(hx):
    b = bytes.fromhex(hx)
    if not b:
        return None
    if b[0] >> 4 != 4:
        return None, None, None, None, b
    ihl = (b[0] & 0xF) * 4
    if ihl < 20 or ihl > len(b):
        return None, None, None, None, b
    proto = b[9]
    total = int.from_bytes(b[2:4], "big")
    body = b[ihl:total] if total <= len(b) else b[ihl:]
    if proto != 6:
        return proto, None, None, None, body
    if len(body) < 20:
        return proto, None, None, None, body
    sp = int.from_bytes(body[0:2], "big")
    dp = int.from_bytes(body[2:4], "big")
    doff = (body[12] >> 4) * 4
    flags = body[13]
    return proto, sp, dp, flags, body[doff:]


print("=" * 78)
print("TEST 1 - does any .php endpoint name ever appear in plaintext?")
print("=" * 78)

for path in PHONES:
    print("\n--- %s" % path.split("\\")[-2])
    blob = bytearray()
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        header = next(rd)
        for row in rd:
            if len(row) < 9:
                continue
            try:
                blob += bytes.fromhex(row[8])
            except Exception:
                pass
    txt = bytes(blob)
    print("    raw payload bytes: %d" % len(txt))
    hits = [n for n in ENDPOINTS if n.encode() in txt]
    print("    .php names present in the clear: %s"
          % (", ".join(hits) if hits else "NONE"))
    # partial: any 'Cmd' occurrence at all?
    print("    literal 'Cmd' occurrences: %d" % txt.count(b"Cmd"))
    print("    plaintext HTTP request lines: %d"
          % len(re.findall(rb"(?:GET|POST) /[!-~]+ HTTP/1\.[01]", txt)))
    for m in re.finditer(rb"(?:GET|POST) (/!-~)?(/[!-~]+) HTTP/1\.[01]", txt):
        print("       ", m.group(0).decode("ascii", "replace"))


print()
print("=" * 78)
print("TEST 2 - all plaintext HTTP request lines, both phones, with time")
print("=" * 78)
for path in PHONES:
    print("\n--- %s" % path.split("\\")[-2])
    seen = 0
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        next(rd)
        for row in rd:
            if len(row) < 9 or row[2] != "tcp":
                continue
            try:
                b = bytes.fromhex(row[8])
            except Exception:
                continue
            m = re.search(rb"(?:GET|POST) (/[!-~]+) HTTP/1\.[01]", b)
            if m:
                seen += 1
                print("   %s  d=%s %s:%s -> %s:%s  %s"
                      % (hhmmss(int(row[0])), row[1], row[3], row[4],
                         row[5], row[6], m.group(0).decode("ascii", "replace")))
    if seen == 0:
        print("   (no plaintext HTTP request line in any outbound packet)")


print()
print("=" * 78)
print("TEST 3 - wire activity %.0fs around score_commit (%s)"
      % (WIN, hhmmss(SCORE)))
print("=" * 78)
for path in PHONES:
    print("\n--- %s" % path.split("\\")[-2])
    syns, big, byport = [], [], collections.Counter()
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        next(rd)
        for row in rd:
            if len(row) < 9:
                continue
            ts = int(row[0])
            if not (SCORE - WIN * 1000 <= ts <= SCORE + WIN * 1000):
                continue
            proto, sp, dp, flags, payload = parse_pkt(row[8])
            if proto != 6:
                continue
            if row[1] == "t":
                byport[(row[5], dp)] += len(payload)
                if flags is not None and (flags & 0x02) and not (flags & 0x10):
                    syns.append((ts, row[5], dp))
                if len(payload) > 400:
                    big.append((ts, row[5], dp, len(payload)))
    print("   new TCP connections (SYN) in window: %d" % len(syns))
    for ts, d, p in sorted(syns):
        mark = "   <<< score_commit" if abs(ts - SCORE) < 3000 else ""
        print("      %s  %s:%d%s" % (hhmmss(ts), d, p, mark))
    print("   outbound payload bytes by destination port:")
    for (d, p), n in sorted(byport.items(), key=lambda kv: -kv[1])[:8]:
        print("      %-40s :6:%-6d %d bytes" % (d, p, n))
    print("   individual >400-byte outbound writes:")
    for ts, d, p, n in sorted(big):
        print("      %s  %s:%d  %d bytes" % (hhmmss(ts), d, p, n))


print()
print("=" * 78)
print("TEST 4 - locate every literal 'Cmd' byte-run in either capture")
print("=" * 78)
for path in PHONES:
    print("\n--- %s" % path.split("\\")[-2])
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.reader(row for row in fh if not row.startswith("#"))
        next(rd)
        n = 0
        for row in rd:
            if len(row) < 9:
                continue
            try:
                b = bytes.fromhex(row[8])
            except Exception:
                continue
            i = b.find(b"Cmd")
            if i < 0:
                continue
            n += 1
            print("   %s d=%s %s:%s->%s:%s proto=%s"
                  % (hhmmss(int(row[0])), row[1], row[3], row[4], row[5],
                     row[6], row[2]))
            print("      context: %r" % b[max(0, i - 40):i + 60])
    if n == 0:
        print("   (zero occurrences)")
