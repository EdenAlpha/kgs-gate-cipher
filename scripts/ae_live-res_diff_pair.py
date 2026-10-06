"""diff_pair.py -- line-level diff between the last normal report and the
report that precedes stall #2."""

import re
import difflib
import urllib.parse

from reassemble import http_messages, safe

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
T0 = 1790385845.048


def hhmmss(ms):
    off = (ms - T0 * 1000.0) / 1000.0
    return "%02d:%06.3f" % (off // 60, off % 60)


def body_text(b):
    txt = b.decode("ascii", "replace")
    if "dat=" not in txt:
        return txt
    raw = urllib.parse.unquote(txt.split("dat=", 1)[1].split("&", 1)[0])
    raw = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(raw) % 2:
        raw = raw[:-1]
    return bytes.fromhex(raw).decode("utf-8", "replace")


want = {}
for ts, p, h, b in http_messages(path):
    if not p.endswith("ReportLog.php"):
        continue
    txt = b.decode("ascii", "replace")
    m = re.search(r"type=([A-Za-z0-9_]+)", txt)
    typ = m.group(1) if m else "-"
    want[(hhmmss(ts), typ)] = body_text(b)

a_key = ("11:59.413", "uds")
b_key = ("13:09.445", "ude")
a = want[a_key].splitlines()
b = want[b_key].splitlines()

print("A = %s type=%s  (%d lines)  -- last normal report" % (a_key[0], a_key[1], len(a)))
print("B = %s type=%s  (%d lines)  -- report preceding STALL #2 at 13:10.869\n"
      % (b_key[0], b_key[1], len(b)))

# collapse pure-counter churn, show real differences
for line in difflib.unified_diff(a, b, fromfile="A normal", tofile="B pre-stall",
                                 n=1, lineterm=""):
    if line.startswith(("+++", "---", "@@")):
        print(line)
        continue
    if line.startswith(("+", "-")):
        print(safe(line))
