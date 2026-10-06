"""Show the shell around the embedded relay in relay_restart_cmd.txt: how it
starts, which token it binds, and whether it preserves the tunnel -- needed to
swap in the /cred-capable relay without dropping the control channel.
"""
import re

raw = open("relay_restart_cmd.txt", "r", encoding="utf-8", errors="replace").read()
raw = raw.replace("\r\n", "\n").strip()
m = re.search(r"echo [A-Za-z0-9+/=]{200,} \| base64 -d > /tmp/relay\.py", raw)
head = raw[: m.start()]
tail = raw[m.end():]
print("=== BEFORE relay.py ===")
print(head)
print("=== AFTER relay.py ===")
print(tail)
