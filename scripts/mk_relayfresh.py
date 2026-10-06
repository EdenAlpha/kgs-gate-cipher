"""Build the correct fresh-run relay command: token generation + tunnel setup
(from relay_start_cmd.txt) with the /cred-capable relay.py (from
relay_restart_cmd.txt). The queued restart-only variant fails on a fresh
runner: `cat /tmp/rt` is empty so the relay refuses to start, and it never
starts a tunnel.
"""
import re

start = open("relay_start_cmd.txt", "r", encoding="utf-8",
             errors="replace").read().replace("\r\n", "\n").strip()
rest = open("relay_restart_cmd.txt", "r", encoding="utf-8",
            errors="replace").read().replace("\r\n", "\n").strip()

pat = r"echo [A-Za-z0-9+/=]{200,} \| base64 -d > /tmp/relay\.py"
m_old = re.search(pat, start)
m_new = re.search(pat, rest)
assert m_old and m_new, "b64 block not found"
new_b64 = re.search(r"echo ([A-Za-z0-9+/=]{200,}) \| base64 -d",
                    m_new.group(0)).group(1)
fixed = (start[: m_old.start()] + "echo " + new_b64 +
         " | base64 -d > /tmp/relay.py" + start[m_old.end():])
assert "\n" not in fixed and "\r" not in fixed
open("relay_fresh_cmd.txt", "wb").write((fixed + "\n").encode())
print("built len:", len(fixed))
print("has token-gen:", "head -c 18 /dev/urandom" in fixed)
print("has tunnel:", "cloudflared" in fixed)
print("head:", fixed[:120])
