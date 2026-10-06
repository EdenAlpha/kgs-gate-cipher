"""Which relay.py variants are embedded in the queued payloads, and do any
serve /cred (the endpoint that would read the staged Play credentials off the
runner so they never pass through chat)? 403 on both probe verbs says no for
the deployed one; check every candidate before rebuilding anything.
"""
import base64
import glob
import re

for fn in sorted(glob.glob("*cmd*.txt")):
    try:
        raw = open(fn, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    m = re.search(r"echo ([A-Za-z0-9+/=]{200,}) \| base64 -d > /tmp/relay\.py", raw)
    if not m:
        continue
    try:
        src = base64.b64decode(m.group(1)).decode("utf-8", "replace")
    except Exception as e:
        print(fn, "-> undecodable:", e)
        continue
    paths = sorted(set(re.findall(r'path == "(/[a-z]+)"', src)))
    print("%-26s relay len=%-6d paths=%s has_cred=%s has_GMAIL=%s"
          % (fn, len(src), paths, "cred" in src.lower(), "GMAIL" in src))
