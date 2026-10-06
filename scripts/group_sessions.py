"""Group the 13 signed exchanges into sessions using the sign's clock field.

Every key scan so far required ONE key to open all recorded replies.  That is
only valid if all the replies were produced under one key.  The request lengths
repeat exactly -- [176,144,160,224] then [176,144,160,224] -- so the same four
requests appear twice, which smells like two separate captures.

The sign carries clock_gettime(CLOCK_BOOTTIME) in ns at bytes 32..36.  That
value is monotonic within one device boot and jumps between captures, so the
gaps in it say directly how many distinct sessions are represented, and which
exchanges belong together.

Prints the table and, per group, whether a single-key scan would be fair.
"""
import base64
import re
import struct

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"

raw = open(LOG, "rb").read().split(b"\n")
exch = []
path = rq = rs = None
for line in raw:
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
        rq = rs = None
    elif line.startswith(b"REQHEX: "):
        try:
            rq = bytes.fromhex(line[8:].strip().decode())
        except ValueError:
            rq = None
    elif line.startswith(b"RESPHEX: "):
        try:
            rs = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            rs = None
        if path:
            exch.append((path, rq, rs))
        path = rq = rs = None

signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", open(MITM, "rb").read())]
n = min(len(exch), len(signs))
pairs = list(zip(exch[:n], signs[:n]))

rows = []
for i, ((path, rq, rs), s) in enumerate(pairs):
    clock, rnd = struct.unpack("<II", s[32:40])
    rows.append((i, clock, rnd, path, len(rq), len(rs)))

rows.sort(key=lambda r: r[1])

print("%-4s %-12s %-10s %-6s %-4s %-6s  %s"
      % ("#", "clock_s", "gap_s", "N", "req", "resp", "endpoint"))
prev = None
groups, cur = [], []
for i, clock, rnd, path, lr, ls in rows:
    sec = clock / 1e9
    gap = "" if prev is None else "%.1f" % (sec - prev)
    print("%-4d %-12.3f %-10s %-6d %-4d %-6d  %s"
          % (i, sec, gap, (rnd ^ clock) & 0xFFFFFFFF, lr, ls, path))
    if prev is None or (sec - prev) > 60:
        groups.append(cur)
        cur = []
    cur.append(i)
    prev = sec
groups.append(cur)
groups = [g for g in groups if g]

print("")
print("groups separated by a >60 s clock gap: %d" % len(groups))
for g in groups:
    print("   exchanges %s   (%d)" % (g, len(g)))

# Also compare content of same-length requests: identical plaintext would mean
# a fixed body (and therefore a fair static-key test); differing content is the
# per-request randomisation we already observed.
print("")
print("same-size request bodies -- are they byte-identical?")
seen = {}
for i, ((path, rq, rs), s) in enumerate(pairs):
    if not rq:
        continue
    key = (path, len(rq))
    if key in seen:
        a = exch[seen[key]][1]
        print("   %s (%d): pair %d vs pair %d -> %s"
              % (path.rsplit("/", 1)[-1], len(rq), seen[key], i,
                 "IDENTICAL" if a == rq else "differs (%d/%d bytes match)"
                 % (sum(1 for x, y in zip(a, rq) if x == y), len(rq))))
    else:
        seen[key] = i
