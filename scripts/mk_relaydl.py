"""Build the relay-start command using the CURRENT repo relay.py.

relay.py now serves GET /ls and GET /dl (ranged) under /tmp/kgs/full, so the
operator can pull the game files to their own machine while the runner is
alive. The hosted runner has died mid-session three times, and every time the
end-of-job artifact upload never ran, taking the capture with it.

Regenerated from the repo file every time -- the cached *_cmd.txt payloads
embed an older relay and were the reason /cred was 403 earlier.
"""
import base64
import re

REPO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"

start = open("relay_start_cmd.txt", "r", encoding="utf-8",
             errors="replace").read().replace("\r\n", "\n").strip()
m_old = re.search(r"echo [A-Za-z0-9+/=]{200,} \| base64 -d > /tmp/relay\.py", start)
assert m_old, "relay_start_cmd.txt shape changed"

src = open(REPO + r"\kgs-login\live\relay.py", "rb").read().replace(b"\r\n", b"\n")
assert b"/dl" in src and b"DL_ROOT" in src
b64 = base64.b64encode(src).decode()

payload = start[:m_old.start()] + "echo " + b64 + \
    " | base64 -d > /tmp/relay.py" + start[m_old.end():]
assert "\n" not in payload
open("relay_dl_cmd.txt", "wb").write((payload + "\n").encode())
print("relay.py bytes:", len(src), "payload len:", len(payload))