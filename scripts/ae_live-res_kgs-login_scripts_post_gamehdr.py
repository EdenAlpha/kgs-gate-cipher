#!/usr/bin/env python3
"""POST the game's own body with the header set the game's own POST sender
builds (recovered from 0x7d03e10 / 0x7d04148)."""
from __future__ import annotations

import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"
BODY = open("getserverenv_body.bin", "rb").read()
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
MAN = 'MAN: "http://schemas.xmlsoap.org/soap/envelope/"; ns=01'


def recv_http(s) -> tuple[str, bytes]:
    """Read one HTTP response without waiting for the connection to close."""
    s.settimeout(20)
    buf = b""
    while b"\r\n\r\n" not in buf:
        b = s.recv(4096)
        if not b:
            break
        buf += b
    head, _, rest = buf.partition(b"\r\n\r\n")
    hdrs = {}
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        hdrs[k.strip().lower()] = v.strip()
    if b"chunked" in head.lower():
        while b"0\r\n\r\n" not in rest:
            b = s.recv(4096)
            if not b:
                break
            rest += b
        out, r = b"", rest
        while r:
            i = r.find(b"\r\n")
            if i < 0:
                break
            n = int(r[:i], 16)
            if n == 0:
                break
            out += r[i + 2:i + 2 + n]
            r = r[i + 2 + n + 2:]
        body = out
    else:
        n = int(hdrs.get(b"content-length", b"0") or 0)
        while len(rest) < n:
            b = s.recv(4096)
            if not b:
                break
            rest += b
        body = rest[:n] if n else rest
    return head.split(b"\r\n", 1)[0].decode("latin1"), body


def send(path, method, body, headers):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    L = [f"{method} {path} HTTP/1.1",
         f"Host: {HOST}",
         "Connection: Keep-Alive",
         "Cache-Control: no-cache",
         "Pragma: no-cache",
         f"User-Agent: {UA}",
         "Accept: */*"] + headers
    L.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    st, bd = recv_http(s)
    s.close()
    return st, bd


CT_XML = 'Content-Type: text/xml; charset="utf-8"'
VARIANTS = [
    ("M-POST + full game header set", "M-POST", [CT_XML, MAN]),
    ("POST  + full game header set", "POST", [CT_XML, MAN]),
    ("M-POST + CT xml only", "M-POST", [CT_XML]),
    ("POST  + CT xml only", "POST", [CT_XML]),
    ("M-POST + CT msgpack", "M-POST",
     ['Content-Type: application/x-msgpack', MAN]),
    ("POST  + form CT + MAN", "POST",
     ["Content-Type: application/x-www-form-urlencoded", MAN]),
]

for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
    path = f"/pes22/gate/gate_{msgid}.php"
    print(f"\n=== {path} ===", flush=True)
    for label, method, hdrs in VARIANTS:
        try:
            st, bd = send(path, method, BODY, hdrs)
        except Exception as e:
            print(f"  {label:34s} ERR {type(e).__name__}: {e}", flush=True)
            continue
        flag = "" if "500" in st else "   <<<<<< DIFFERENT"
        print(f"  {label:34s} {st}  {bd[:260]!r}{flag}", flush=True)
