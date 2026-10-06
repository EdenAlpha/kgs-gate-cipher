"""diff_types.py -- which sections/keys distinguish an `ude` (stall) report
from a normal `uds` report?"""

import re
import urllib.parse
import collections

from reassemble import http_messages, safe

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
T0 = 1790385845.048
STALLS = [1790386488724, 1790386635917, 1790387153392]


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


def sections(dat):
    return [ln.strip() for ln in dat.splitlines() if ln.startswith("## ")]


by_type = collections.defaultdict(list)
for ts, p, h, b in http_messages(path):
    if not p.endswith("ReportLog.php"):
        continue
    txt = b.decode("ascii", "replace")
    m = re.search(r"type=([A-Za-z0-9_]+)", txt)
    typ = m.group(1) if m else "-"
    by_type[typ].append((ts, body_text(b)))

for typ in sorted(by_type):
    print("=" * 78)
    print("type=%s   n=%d" % (typ, len(by_type[typ])))
    for ts, dat in by_type[typ]:
        mark = ""
        if any(abs(ts - s) < 5000 for s in STALLS):
            mark = "   <<< STALL"
        print("   %s%s" % (hhmmss(ts), mark))
    # union of sections
    sects = collections.Counter()
    for ts, dat in by_type[typ]:
        for s in sections(dat):
            sects[s] += 1
    print("   sections present in ALL of them:")
    for s, n in sorted(sects.items()):
        flag = "" if n == len(by_type[typ]) else "   (only %d/%d)" % (n, len(by_type[typ]))
        print("      %-52s%s" % (s, flag))

# key-level diff: which lines appear in every ude but never in any uds
def keys(dat):
    out = set()
    for ln in dat.splitlines():
        for k in re.findall(r'"([A-Za-z_][A-Za-z0-9_ :]{2,40})"\s*:', ln):
            out.add(k)
    return out


ude_keys = set()
uds_keys = set()
for ts, dat in by_type.get("ude", []):
    ude_keys |= keys(dat)
for ts, dat in by_type.get("uds", []):
    uds_keys |= keys(dat)

print("\n" + "=" * 78)
print("keys seen in type=ude but NEVER in type=uds:")
for k in sorted(ude_keys - uds_keys):
    print("   ", k)
print("\nkeys seen in type=uds but NEVER in type=ude:")
for k in sorted(uds_keys - ude_keys):
    print("   ", k)
