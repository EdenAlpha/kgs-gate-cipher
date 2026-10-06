#!/usr/bin/env python3
"""The gRPC path.  `Def_Online_gRPC_server_path` sits right beside
`gate/gate_` in the string table, and `CMD_CONNECT_GRPC` exists.

If login is gRPC the PHP gate is a dead legacy path -- which fits every
blank-500 result.  Find the gRPC service/method names and the server path.
"""
from __future__ import annotations

import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

data = open(SO, "rb").read()


def ctx(pat: bytes, before=120, after=200, limit=12):
    print(f"\n=== {pat.decode('latin1', 'replace')} ===", flush=True)
    n = 0
    i = 0
    while n < limit:
        i = data.find(pat, i)
        if i < 0:
            break
        st = i
        while st > 0 and (32 <= data[st - 1] < 127 or data[st - 1] == 0):
            st -= 1
        en = data.find(b"\x00\x00", i)
        chunk = data[max(0, i - before):i + after]
        parts = [p for p in chunk.split(b"\x00") if len(p) > 2]
        print(f"  @{i:#x}", flush=True)
        for p in parts[-8:]:
            print(f"      {p[:110]!r}", flush=True)
        i += len(pat)
        n += 1


# 1. the gRPC server path and its neighbours
ctx(b"Def_Online_gRPC_server_path", 200, 300, 2)
ctx(b"grpc_heartbeat_interval_msec", 200, 200, 2)

# 2. gRPC full method names look like  /pkg.Service/Method
print("\n=== gRPC full-method paths (/a.b/C) ===", flush=True)
found = set()
for m in re.finditer(rb"/[A-Za-z][A-Za-z0-9_]{1,40}\.[A-Za-z][A-Za-z0-9_]{1,40}/[A-Za-z][A-Za-z0-9_]{1,60}", data):
    s = m.group(0).decode("latin1")
    if s not in found:
        found.add(s)
        print(f"   {m.start():#x}  {s}", flush=True)
    if len(found) > 40:
        break

# 3. protobuf service / rpc names
print("\n=== strings mentioning grpc / rpc / .proto / Service ===", flush=True)
seen = set()
for m in re.finditer(rb"[ -~]{4,70}", data):
    s = m.group(0)
    low = s.lower()
    if (b"grpc" in low or b".proto" in low or low.endswith(b"service")
            or b"/stub" in low or b"channel" in low) and s not in seen:
        seen.add(s)
        print(f"   {m.start():#x}  {s[:70]!r}", flush=True)
        if len(seen) > 50:
            break

# 4. CMD_ names that mention GRPC / CONNECT
print("\n=== CMD_ names mentioning GRPC/CONNECT/SESSION/AUTH ===", flush=True)
for m in re.finditer(rb"CMD_[A-Z][A-Z0-9_]{2,60}", data):
    s = m.group(0).decode()
    if any(k in s for k in ("GRPC", "CONNECT", "SESSION", "AUTH", "LOGIN",
                            "TOKEN", "HEARTBEAT", "KGS")):
        if s not in seen:
            seen.add(s)
            print(f"   {m.start():#x}  {s}", flush=True)
sys = None
