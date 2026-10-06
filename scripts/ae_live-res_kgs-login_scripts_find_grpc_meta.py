#!/usr/bin/env python3
"""Find the gRPC metadata keys the client attaches.

grpc-status:14 is constant no matter what we send, which smells like an
auth/interceptor rejection before the message is read.  gRPC metadata keys
are short ASCII strings referenced from OnlineSystemgRPCClient.cpp.  Look
for key-shaped strings near the gRPC client source paths.
"""
from __future__ import annotations

import re

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

data = open(SO, "rb").read()


def region(label: str, needle: bytes, before=1500, after=1500):
    i = data.find(needle)
    if i < 0:
        print(f"\n=== {label}: NOT FOUND ===", flush=True)
        return
    print(f"\n=== {label} @ {i:#x} ===", flush=True)
    st = max(0, i - before)
    for m in re.finditer(rb"[ -~]{3,80}", data[st:i + after]):
        t = m.group(0).decode("latin1")
        print(f"    [{st + m.start():#x}] {t[:90]!r}", flush=True)


# 1. the gRPC client source-file assert strings (give the class structure)
region("OnlineSystemgRPCClient.cpp", b"OnlineSystemgRPCClient.cpp", 900, 900)

# 2. Protocol source (the proto builder)
i = data.find(b"OnlineSystem\\gRPC\\Protoco")
if i >= 0:
    print(f"\n=== Protocol source @ {i:#x} ===", flush=True)
    for m in re.finditer(rb"[ -~]{3,80}", data[max(0, i - 600):i + 600]):
        print(f"    [{max(0,i-600) + m.start():#x}] "
              f"{m.group(0).decode('latin1')[:90]!r}", flush=True)

# 3. gRPC metadata key candidates
print("\n\n=== metadata-key shaped strings (x-*, *-bin, short tokens) ===",
      flush=True)
seen = set()
for m in re.finditer(rb"\x00((?:x-)?[a-z][a-z0-9_\-]{2,30}(?:-bin|-token|-id|-key|-auth|-session)?)\x00", data):
    s = m.group(1).decode()
    low = s.lower()
    if any(k in low for k in ("token", "auth", "session", "user", "sign",
                              "hash", "device", "ticket", "key", "secret",
                              "cert", "uuid", "udid", "guest")):
        if s not in seen:
            seen.add(s)
            print(f"    [{m.start()+1:#x}] {s}", flush=True)
        if len(seen) > 80:
            break

# 4. the mobile_log_context / custom grpc args
print("\n=== custom grpc channel args ===", flush=True)
for m in re.finditer(rb"\x00(grpc\.[a-z0-9_.]{4,50})\x00", data):
    s = m.group(1).decode()
    if any(k in s for k in ("log", "auth", "user", "cred", "target",
                            "authority", "id", "token")):
        print(f"    [{m.start()+1:#x}] {s}", flush=True)
