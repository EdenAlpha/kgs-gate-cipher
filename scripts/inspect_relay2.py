"""Detail the /cred-capable relay: every endpoint it serves, how it resolves
the credential, and which env/file names it reads -- so the replacement can be
verified before it replaces a working (if limited) relay.
"""
import base64
import re

raw = open("relay_restart_cmd.txt", "r", encoding="utf-8", errors="replace").read()
m = re.search(r"echo ([A-Za-z0-9+/=]{200,}) \| base64 -d > /tmp/relay\.py", raw)
src = base64.b64decode(m.group(1)).decode("utf-8", "replace")

lines = src.splitlines()
for i, l in enumerate(lines, 1):
    s = l.strip()
    if (s.startswith("def do_") or s.startswith("class ") or "path" in s and ("==" in s or "startswith" in s)
            or "GMAIL" in s or "GPASS" in s or "environ" in s or "creds" in s
            or "input text" in s or "adb" in s):
        print("%4d %s" % (i, s))
