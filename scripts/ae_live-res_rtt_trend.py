"""rtt_trend.py -- for every plaintext ReportLog on both phones, extract the
RTT scalars, the sendCnt rates, and the packet-size profile of the tail dump.
Goal: is there a transport signature at the pre-stall (type=ude) reports?"""

import re
import urllib.parse
import collections

from reassemble import http_messages, safe

PHONES = [r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv",
          r"captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"]

T0 = 1790385845.048
CLIFFS = [1790386488724, 1790386635917, 1790387153392]


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


for path in PHONES:
    print("=" * 78)
    print(path)
    print("=" * 78)

    rows = []
    prev = None
    for ts, p, h, b in http_messages(path):
        if not p.endswith("ReportLog.php"):
            continue
        txt = b.decode("ascii", "replace")
        m = re.search(r"type=([A-Za-z0-9_]+)", txt)
        typ = m.group(1) if m else "-"
        dat = body_text(b)

        rtts = re.findall(r'\$\{"rtt:":(-?\d+)\}', dat)
        arrs = re.findall(r'\$\{"rtt":\[([^\]]*)\]\}', dat)
        cnts = [int(x) for x in re.findall(r'\$\{"sendCnt":(\d+)\}', dat)]
        sizes = [int(x) for x in re.findall(r"\[ (\d+) bytes \]", dat)]
        conn = len(re.findall(r'"status":"CONNECTED"', dat))
        restr = len(re.findall(r'"status":"RESTRAINED"', dat))
        close = len(re.findall(r'"ev":"CLOSE"', dat))

        rate = ""
        if prev is not None and cnts and prev[1]:
            dt = (ts - prev[0]) / 1000.0
            if dt > 0 and len(cnts) == len(prev[1]):
                rate = "/".join("%.1f" % ((c - o) / dt)
                                for c, o in zip(cnts, prev[1]))
        prev = (ts, cnts)

        mark = ""
        for i, c in enumerate(CLIFFS):
            if 0 <= (c - ts) < 15000:
                mark = "  <<< %d s before STALL %d" % ((c - ts) / 1000.0, i + 1)
                break
        if mark == "" and any(0 <= (ts - c) < 15000 for c in CLIFFS):
            mark = "  <<< just after a STALL"

        prof = collections.Counter(sizes)
        top = ",".join("%d:%d" % (s, n) for s, n in
                       sorted(prof.items(), key=lambda kv: -kv[1])[:6])

        rows.append((hhmmss(ts), typ, ",".join(rtts), ";".join(arrs),
                     ",".join(str(c) for c in cnts), rate, top,
                     "%d/%d" % (conn, restr), close, mark))

    print("%-11s %-4s %-6s %-14s %-16s %-14s %-34s %-7s %s"
          % ("time", "type", "rtt:", "rtt[]", "sendCnt", "rate/s",
             "tail packet sizes (size:count)", "C/R", "close"))
    for r in rows:
        print("%-11s %-4s %-6s %-14s %-16s %-14s %-34s %-7s %-24s%s"
              % (r[0], r[1], r[2], r[3], r[4], r[5], r[6][:34], r[7],
                 ("CLOSEx%d" % r[8]) if r[8] else "", r[9]))
    print()
