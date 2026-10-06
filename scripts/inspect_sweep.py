"""Decode sweep_cmd.txt: where does sweep_fixed.sh come from on the runner?"""
import base64
import re

raw = open("sweep_cmd.txt", "r", encoding="utf-8", errors="replace").read()
raw = raw.replace("\r\n", "\n").strip()
print("total len:", len(raw))
m = re.search(r"echo ([A-Za-z0-9+/=]{200,}) \| base64 -d > (\S+)", raw)
if m:
    print("target:", m.group(2))
    src = base64.b64decode(m.group(1)).decode("utf-8", "replace")
    print("decoded len:", len(src))
    print(src[:1500])
else:
    print("--- raw head ---")
    print(raw[:1500])
