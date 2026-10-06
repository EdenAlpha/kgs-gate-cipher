#!/usr/bin/env python3
"""Locate the game's ChangeServer.bin on the info host."""
from __future__ import annotations

import socket
import ssl

H = "info.service.konami.net"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"

PATHS = [
    "/XWW020-E1/info/ChangeServer.bin",
    "/XWW020-E1/info/ChangeServer",
    "/XWW020-E1/info/changeserver.bin",
    "/XWW020-E1/ChangeServer.bin",
    "/ChangeServer.bin",
    "/XWW020-E1/info/index.html",
    "/XWW020-E1/info/list.json",
    "/XWW020-E2/info/ChangeServer.bin",
    "/XWW021-E1/info/ChangeServer.bin",
    "/XWW020-E1/info/ChangeServer.bin?1",
]


def get(p):
    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.create_connection((H, 443), timeout=20),
                            server_hostname=H)
        s.sendall((f"GET {p} HTTP/1.1\r\nHost: {H}\r\nConnection: close\r\n"
                   f"User-Agent: {UA}\r\nAccept: */*\r\n\r\n").encode())
        d = b""
        while True:
            b = s.recv(4096)
            if not b:
                break
            d += b
            if len(d) > 40000:
                break
        s.close()
        st = d.split(b"\r\n", 1)[0].decode("latin1")
        body = d.partition(b"\r\n\r\n")[2]
        return st, body
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}", b""


for p in PATHS:
    st, body = get(p)
    flag = "" if "404" in st else "   <<<<<<"
    print(f"  {p:46s} {st}{flag}")
    if body and b"404" not in body[:200] and b"Not Found" not in body:
        print("      ", body[:400])
