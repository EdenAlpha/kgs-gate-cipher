"""Rebuild the arm payload from the CURRENT repo arm_recorder.sh.

The payload used on run 37332769341 (arm_cmd.txt) embeds an OLD copy of
arm_recorder.sh: it went straight from "ca hash:" to "arming DNAT" and never
printed the bind-mount lines that put the CA into the Conscrypt apex store,
which is where apps look. So the CA existed but the app rejected the proxy
("tls alert certificate unknown") and the game could not reach the server at
all. Always regenerate this payload from the repo file, never reuse the
cached *_cmd.txt.
"""
import base64

REPO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
src = open(REPO + r"\kgs-login\live\arm_recorder.sh", "rb").read()
src = src.replace(b"\r\n", b"\n")
assert b"\r" not in src
text = src.decode()

for marker in ("mount --bind", "ctl.restart zygote", "RECORDER ARMED"):
    assert marker in text, "arm_recorder.sh is missing %r" % marker

b64 = base64.b64encode(src).decode()
payload = ("exec echo ARM-FRESH; echo %s | base64 -d > /tmp/kgs/arm_recorder.sh && "
           "bash /tmp/kgs/arm_recorder.sh" % b64).encode() + b"\n"
open("arm_fresh_cmd.txt", "wb").write(payload)
print("script bytes:", len(src), "payload len:", len(payload))