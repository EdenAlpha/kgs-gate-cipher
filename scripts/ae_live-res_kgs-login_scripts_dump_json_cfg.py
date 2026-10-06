#!/usr/bin/env python3
"""Dump the embedded JSON config block that controls the HTTP vs gRPC path.

Found fragment:  ..."use_http_command": false},"connect_grpc_task": {"disable": true}}...

This is the game's runtime online config.  Read the whole block.
"""
from __future__ import annotations

import json
import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

data = open(SO, "rb").read()

# --- expand outward from the known fragment to the whole JSON blob -------
i = data.find(b'"connect_grpc_task"')
print(f"fragment at {i:#x}", flush=True)

# walk back to the matching '{'
depth = 0
st = i
while st > 0:
    c = data[st]
    if c == ord("}"):
        depth += 1
    elif c == ord("{"):
        if depth == 0:
            break
        depth -= 1
    st -= 1

# walk forward to the matching '}'
depth = 0
en = i
while en < len(data):
    c = data[en]
    if c == ord("{"):
        depth += 1
    elif c == ord("}"):
        depth -= 1
        if depth == 0:
            en += 1
            break
    en += 1

blob = data[st:en]
print(f"JSON block {st:#x}..{en:#x}  {len(blob)} bytes\n", flush=True)
try:
    j = json.loads(blob.decode("utf-8", "replace"))
    print(json.dumps(j, indent=1), flush=True)
except Exception as e:
    print(f"json parse failed: {e}", flush=True)
    print(blob.decode("latin1", "replace")[:6000], flush=True)


# --- also find every JSON-ish block with online/grpc/command keys ---------
print("\n\n=== other JSON config blocks with online keys ===", flush=True)
for m in re.finditer(rb'\{[^{}]{0,400}(?:grpc|command|online|gate|use_http)[^{}]{0,400}\}',
                     data):
    s = m.group(0).decode("latin1", "replace")
    if s.startswith("{") and ("disable" in s or "use_" in s or "path" in s):
        print(f"  {m.start():#x}  {s[:400]}", flush=True)
