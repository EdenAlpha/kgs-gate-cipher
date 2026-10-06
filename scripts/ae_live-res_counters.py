"""counters.py -- which numeric counters actually advance across each report,
and which appear frozen?  Distinguishes "counter stopped" from "field is a
per-report snapshot"."""

import re
import urllib.parse
import collections

from reassemble import http_messages

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


reps = []
for ts, p, h, b in http_messages(path):
    if not p.endswith("ReportLog.php"):
        continue
    txt = b.decode("ascii", "replace")
    m = re.search(r"type=([A-Za-z0-9_]+)", txt)
    reps.append((ts, m.group(1) if m else "-", body_text(b)))

# every integer-valued key anywhere in the body, plus line context
snap = []
for ts, typ, dat in reps:
    d = {}
    for k, v in re.findall(r'"([A-Za-z0-9_]+)"\s*:\s*(\d+)', dat):
        d[k + ("#2" if k in d else "")] = int(v)
    # bare ${"key":N} form
    for k, v in re.findall(r'\$\{"([A-Za-z0-9_]+)":(\d+)\}', dat):
        d["$" + k] = int(v)
    snap.append((ts, typ, d))

allkeys = []
for _, _, d in snap:
    for k in d:
        if k not in allkeys:
            allkeys.append(k)

print("counter".ljust(26),
      "  ".join("%s" % hhmmss(ts)[3:8] for ts, _, _ in snap))
print("type".ljust(26),
      "  ".join("%-5s" % typ for _, typ, _ in snap))
print("-" * 118)

for k in allkeys:
    vals = [str(d[k]) if k in d else "-" for _, _, d in snap]
    nums = [d[k] for _, _, d in snap if k in d]
    froze = all(nums[i] == nums[i + 1] for i in range(len(nums) - 1)) if len(nums) > 1 else None
    mono = all(nums[i] <= nums[i + 1] for i in range(len(nums) - 1)) if len(nums) > 1 else None
    tag = ""
    if froze is True:
        tag = "  == constant"
    elif mono:
        tag = "  (non-decreasing)"
    else:
        # detect a frozen gap: v[i] == v[i+1] for some consecutive pair
        gaps = [i for i in range(len(nums) - 1) if nums[i] == nums[i + 1]]
        if gaps:
            tag = "  !! FROZEN at step(s) %s" % gaps
        else:
            tag = "  (varies)"
    if "FROZEN" in tag or "constant" in tag or k.startswith(("$sendCnt", "$rtt")):
        print(k.ljust(26), "  ".join(v.rjust(5) for v in vals), tag)
