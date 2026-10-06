#!/usr/bin/env python3
"""Hunt ChangeServer.bin -- the runtime config the game reads at startup.

It is NOT in any APK split, so the app downloads it.  The binary carries
    https://info.service.konami.net/XWW020-E1/info/   +   ChangeServer.bin
which 404s at face value.  Try the plausible variants and dump whatever the
info host will give us.
"""
from __future__ import annotations

import re
import socket
import ssl

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
HOST = "info.service.konami.net"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"

data = open(SO, "rb").read()

print("=== context around the /ChangeServer.bin literal ===")
for m in re.finditer(rb"/?ChangeServer\.bin", data):
    st = m.start()
    a = st - 160
    while a > 0 and (32 <= data[a - 1] < 127 or data[a - 1] == 0):
        a -= 1
    chunk = data[a:st + 120]
    parts = [p for p in chunk.split(b"\x00") if len(p) > 2]
    print(f"  at {st:#x}:")
    for p in parts[-6:]:
        print(f"      {p[:110]!r}", flush=True)

print("\n=== every URL-ish string mentioning info.service or /info/ ===")
for m in re.finditer(rb"[ -~]{0,60}(?:info\.service|/info/)[ -~]{0,80}",
                     data):
    print(f"   {m.start():#x}  {m.group(0)[:120]!r}")


def get(path, host=HOST, port=443, method="GET", body=None, ctype=None,
        extra=()):
    try:
        if port == 443:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            s = ctx.wrap_socket(socket.create_connection((host, port),
                                                         timeout=20),
                                server_hostname=host)
        else:
            s = socket.create_connection((host, port), timeout=20)
        L = [f"{method} {path} HTTP/1.1", f"Host: {host}",
             "User-Agent: " + UA, "Accept: */*", "Connection: close"]
        if ctype:
            L.append("Content-Type: " + ctype)
        for e in extra:
            L.append(e)
        if body is not None:
            L.append(f"Content-Length: {len(body)}")
        s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + (body or b""))
        s.settimeout(20)
        d = b""
        while len(d) < 262144:
            b = s.recv(8192)
            if not b:
                break
            d += b
        s.close()
        st = d.split(b"\r\n", 1)[0].decode("latin1")
        return st, d.partition(b"\r\n\r\n")[2]
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}", b""


PATHS = [
    "/XWW020-E1/info/ChangeServer.bin",
    "/XWW020-E1/info/ChangeServer.bin?ver=6.0.1",
    "/XWW020-E1/info/ChangeServer.bin?version=6.0.1",
    "/XWW020-E1/info/ChangeServer.bin?lang=en",
    "/XWW020-E1/info/ChangeServer.php",
    "/XWW020-E1/info/ChangeServer",
    "/XWW020-E1/info/changeserver.bin",
    "/XWW020-E1/info/changeserver",
    "/XWW020-E1/info/ChangeServerList.bin",
    "/XWW020-E1/info/ServerList.bin",
    "/XWW020-E1/info/index.php",
    "/XWW020-E1/info/index.bin",
    "/XWW020-E1/ChangeServer.bin",
    "/XWW020-E1/info/",
    "/XWW020-E1/info/ChangeServer.bin/",
]

print("\n=== probing the info host ===", flush=True)
for p in PATHS:
    st, bd = get(p)
    flag = "" if "404" in st else "   <<<<<<"
    print(f"  {p:48s} {st}{flag}", flush=True)
    if bd and "404" not in st and len(bd) > 40:
        print(f"      body {len(bd)}B: {bd[:300]!r}", flush=True)
        open("ChangeServer.bin", "wb").write(bd)
        print("      saved to ChangeServer.bin", flush=True)
