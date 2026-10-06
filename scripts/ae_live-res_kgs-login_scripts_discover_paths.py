#!/usr/bin/env python3
"""Every URL path the game could build, then probe them all.

We have been guessing paths.  Pull every path-shaped string out of the
binary (the app can only request what it contains) and test them all at the
known host.  Anything that is not 404/500 is news.
"""
from __future__ import annotations

import re
import socket
import ssl
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
HOST = "pes22-game.cs.konami.net"

data = open(SO, "rb").read()


def collect(pattern: bytes, minlen=4, maxn=4000) -> set[str]:
    out = set()
    for m in re.finditer(pattern, data):
        st = m.start()
        while st > 0 and (32 <= data[st - 1] < 127):
            st -= 1
        en = data.find(b"\x00", m.end())
        if en < 0:
            en = m.end() + 60
        s = data[st:min(en, st + 120)].decode("latin1", "replace")
        s = s.strip().strip('"').strip("'")
        if minlen <= len(s) <= 110 and s.startswith("/"):
            out.add(s)
        if len(out) >= maxn:
            break
    return out


print("=== path-shaped strings in the binary ===", flush=True)
paths = set()
paths |= collect(rb"/[A-Za-z0-9_\-./]{3,80}\.php")
paths |= collect(rb"/api/[A-Za-z0-9_\-./]{2,60}")
paths |= collect(rb"/v[0-9]/[A-Za-z0-9_\-./]{2,60}")
paths |= collect(rb"/pes22/[A-Za-z0-9_\-./]{2,60}")
paths |= collect(rb"/[A-Za-z][A-Za-z0-9_\-]{2,30}\.php")
for p in sorted(paths):
    print(f"   {p}", flush=True)
print(f"   total {len(paths)}\n", flush=True)


def probe(path: str) -> tuple[str, bytes]:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=15),
                        server_hostname=HOST)
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
               f"Connection: close\r\nAccept: */*\r\n"
               f"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)\r\n"
               f"\r\n").encode())
    s.settimeout(15)
    d = b""
    while len(d) < 8192:
        b = s.recv(4096)
        if not b:
            break
        d += b
    s.close()
    st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return st, d.partition(b"\r\n\r\n")[2][:120]


# mount points to try each basename under
MOUNTS = ["/", "/pes22/", "/pes22/gate/", "/pes22/api/", "/api/", "/gate/",
          "/pes22/gate/gate_", "/pes22/cmd/", "/cmd/", "/ntl/api/"]

basenames = set()
for p in paths:
    basenames.add(p.lstrip("/"))
    basenames.add(p.rsplit("/", 1)[-1])

print("=== probing (non-404/500 flagged) ===", flush=True)
hits = []
for mount in MOUNTS:
    for base in sorted(basenames):
        path = mount + base
        try:
            st, bd = probe(path)
        except Exception:
            continue
        code = st.split(" ")[1] if st.startswith("HTTP") else st
        if code not in ("404", "500"):
            print(f"   {path:64s} {st}  {bd[:80]!r}", flush=True)
            hits.append((path, st, bd))

print(f"\n=== {len(hits)} responses that were not 404/500 ===", flush=True)
for p, st, bd in hits:
    print(f"   {p:64s} {st}  {bd[:80]!r}", flush=True)
sys.exit(0)
