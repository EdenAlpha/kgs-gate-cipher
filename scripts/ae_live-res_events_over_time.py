"""events_over_time.py -- what status/event history does the plaintext channel
actually carry, and when?"""

import re
import urllib.parse

from reassemble import http_messages, safe

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
T0 = 1790385845.048
SCORE_COMMIT = 1790387785479
CLIFFS = [1790386488724, 1790386635917, 1790387153392]


def hhmmss(ms):
    off = (ms - T0 * 1000.0) / 1000.0
    return "%02d:%06.3f" % (off // 60, off % 60)


msgs = http_messages(path)

# anchor the NTL session clock: GateInfo is the bootstrap request
ntl_epoch = None
for ts, p, h, b in msgs:
    if p.endswith("GateInfo.php"):
        ntl_epoch = ts
        break
print("NTL clock origin assumed at GateInfo: %s (session-relative)" % hhmmss(ntl_epoch))
print("score_commit: %s    cliffs: %s\n" % (hhmmss(SCORE_COMMIT),
                                            ", ".join(hhmmss(c) for c in CLIFFS)))

for ts, p, h, b in msgs:
    if not p.endswith("ReportLog.php"):
        continue
    txt = b.decode("ascii", "replace")
    m = re.search(r"type=([A-Za-z0-9_]+)", txt)
    typ = m.group(1) if m else "-"
    raw = urllib.parse.unquote(txt.split("dat=", 1)[1].split("&", 1)[0])
    raw = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(raw) % 2:
        raw = raw[:-1]
    dat = bytes.fromhex(raw).decode("utf-8", "replace")

    marks = ""
    if any(abs(ts - c) < 5000 for c in CLIFFS):
        marks = "   <<< within 5 s of a STALL"
    elif abs(ts - SCORE_COMMIT) < 60000:
        marks = "   <<< near score_commit"
    print("=" * 78)
    print("%s  type=%-4s  %d bytes%s" % (hhmmss(ts), typ, len(b), marks))

    lines = dat.splitlines()
    # section headers + everything under EventHistory / any status line
    in_hist = False
    for ln in lines:
        if ln.startswith("## "):
            in_hist = ln.strip() in ("## EventHistory",)
            if in_hist:
                print("   %s" % ln.strip())
            continue
        if in_hist and ln.strip():
            t = None
            mt = re.search(r'"t":(\d+)', ln)
            if mt:
                t = int(mt.group(1))
            abs_s = ""
            if t is not None and ntl_epoch:
                abs_s = "   [NTL t=%.1f s -> session %s]" % (
                    t / 1000.0, hhmmss(ntl_epoch + t))
            print("      %s%s" % (safe(ln.strip()[:170]), abs_s))
        elif re.search(r'"(status|Abort)"', ln):
            print("   %s" % safe(ln.strip()[:170]))
