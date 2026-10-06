"""scan_reason.py -- does Konami's *plaintext* HTTP channel carry a disconnect
reason?  Decodes every body on both phones and reports the `type=` discriminator
plus every reason-ish line."""

import csv
import re
import urllib.parse
import collections

from reassemble import http_messages, safe

PHONES = [r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv",
          r"captures\match-2026-09-26\z2-elijah-hotspot-owner\passthrough_capture.csv"]

KEYWORDS = [
    "abnormal", "disconnect", "disconnet", "reason", "giveup", "give_up",
    "forfeit", "background", "blocked", "watchdog", "intentional", "strange",
    "error", "code", "timeout", "fail", "abort", "close", "formally",
]

FIELDS_FROM_CMD = [   # the fields section 2 says belong to CmdGetVscomGameResult.php
    "game_id", "abnormalend_reason", "is_problem", "is_stun_keep_alive_failed",
    "is_network_blocked_disconn", "is_background_timeout", "is_background_at_match",
    "user_network_status", "error_code", "intentional_give_up",
]

for path in PHONES:
    print("=" * 78)
    print(path)
    print("=" * 78)
    msgs = http_messages(path)
    types = collections.Counter()
    for ts, p, h, b in msgs:
        txt = b.decode("ascii", "replace")
        m = re.search(r"type=([A-Za-z0-9_]+)", txt)
        types[(p, m.group(1) if m else "-")] += 1

    print("\n[type= discriminator per endpoint]")
    for (p, t), n in sorted(types.items()):
        print("   %-42s type=%-6s x%d" % (p, t, n))

    print("\n[do any CmdGetVscomGameResult fields appear anywhere in plaintext?]")
    alltext = []
    for ts, p, h, b in msgs:
        txt = b.decode("ascii", "replace")
        if "dat=" not in txt:
            alltext.append((ts, p, txt))
            continue
        raw = urllib.parse.unquote(txt.split("dat=", 1)[1].split("&", 1)[0])
        raw = re.sub(r"[^0-9a-fA-F]", "", raw)
        if len(raw) % 2:
            raw = raw[:-1]
        try:
            dat = bytes.fromhex(raw).decode("utf-8", "replace")
        except Exception:
            dat = txt
        alltext.append((ts, p, dat))
    for f in FIELDS_FROM_CMD:
        hits = [ts for ts, p, d in alltext if f in d]
        print("   %-30s : %s" % (f, ("FOUND at %s" % hits) if hits else "never"))

    print("\n[all reason-ish lines, de-duplicated]")
    seen = set()
    for ts, p, d in alltext:
        for ln in d.splitlines():
            low = ln.lower()
            hits = [k for k in KEYWORDS if k in low]
            if not hits:
                continue
            key = ln.strip()[:150]
            if key in seen:
                continue
            seen.add(key)
            print("   [%-12s] %s" % (",".join(hits[:3]), safe(key)))
    print()
