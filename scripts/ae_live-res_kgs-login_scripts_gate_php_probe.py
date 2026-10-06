#!/usr/bin/env python3
"""What does the shared gate dispatcher (/pes22/gate.php) want?

It fatals identically to the per-command scripts, so it dies before reading
the body.  Probe the shapes a PHP router normally needs: the command in the
query string, or a form field naming the command.
"""
from __future__ import annotations

import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
BODY = open("getserverenv_body.bin", "rb").read()
HEX = BODY.hex()
FORM = "application/x-www-form-urlencoded"


def req(method, path, body=b"", ct=None, extra=()):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=20),
                        server_hostname=HOST)
    L = [f"{method} {path} HTTP/1.1", f"Host: {HOST}", f"User-Agent: {UA}",
         "Accept: */*", "Connection: close"]
    if ct:
        L.append("Content-Type: " + ct)
    for e in extra:
        L.append(e)
    if body:
        L.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    s.settimeout(20)
    d = b""
    while len(d) < 40000:
        b = s.recv(4096)
        if not b:
            break
        d += b
    s.close()
    st = d.split(b"\r\n", 1)[0].decode("latin1")
    bd = d.partition(b"\r\n\r\n")[2]
    if b"chunked" in d[:200].lower():
        out, r = b"", bd
        while r:
            i = r.find(b"\r\n")
            if i < 0:
                break
            n = int(r[:i], 16)
            if n == 0:
                break
            out += r[i + 2:i + 2 + n]
            r = r[i + 2 + n + 2:]
        bd = out
    return st, bd


CASES = [
    ("GET ?msgid", "/pes22/gate.php?msgid=CMD_LOGIN", b"", None),
    ("GET ?cmd", "/pes22/gate.php?cmd=CMD_LOGIN", b"", None),
    ("GET ?c", "/pes22/gate.php?c=CMD_LOGIN", b"", None),
    ("GET ?api", "/pes22/gate.php?api=CMD_LOGIN", b"", None),
    ("GET ?m", "/pes22/gate.php?m=CMD_LOGIN", b"", None),
    ("GET ?name", "/pes22/gate.php?name=CMD_LOGIN", b"", None),
    ("GET ?id", "/pes22/gate.php?id=CMD_LOGIN", b"", None),
    ("GET ?service", "/pes22/gate.php?service=CMD_LOGIN", b"", None),
    ("POST msgid field", "/pes22/gate.php", b"msgid=CMD_LOGIN", FORM),
    ("POST cmd field", "/pes22/gate.php", b"cmd=CMD_LOGIN", FORM),
    ("POST c field", "/pes22/gate.php", b"c=CMD_LOGIN", FORM),
    ("POST msgid+req", "/pes22/gate.php",
     b"msgid=CMD_LOGIN&req=" + HEX.encode(), FORM),
    ("POST req only", "/pes22/gate.php", b"req=" + HEX.encode(), FORM),
    ("POST raw msgpack", "/pes22/gate.php", BODY, FORM),
]

for label, path, body, ct in CASES:
    try:
        st, bd = req("POST" if body else "GET", path, body, ct)
    except Exception as e:
        print(f"  {label:22s} ERR {type(e).__name__}: {e}")
        continue
    flag = "" if "500" in st else "    <<<<<< NOT 500"
    print(f"  {label:22s} {st}  {bd[:200]!r}{flag}")
