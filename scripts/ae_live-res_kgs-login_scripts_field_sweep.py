#!/usr/bin/env python3
"""One compact sweep of the request wrapping against gate_CMD_LOGIN.php.

The server runs the script and dies (500) before it looks at our input, for
every framing tried so far.  `gate.php` at /pes22/gate.php fatals the same way,
which points at a shared dispatcher that wants one named field.  This tries the
plausible names/encodings in a single pass.
"""
from __future__ import annotations

import base64
import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"
PATH = "/pes22/gate/gate_CMD_LOGIN.php"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
BODY = open("getserverenv_body.bin", "rb").read()

NAMES = ["req", "dat", "data", "body", "msg", "message", "packet", "payload",
         "param", "q", "input", "request", "param1", "cmd", "com"]


def post(path, body, ct, query=""):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=20),
                        server_hostname=HOST)
    head = (f"POST {path}{query} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"User-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n"
            f"Content-Type: {ct}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n")
    s.sendall(head.encode() + body)
    s.settimeout(20)
    d = b""
    while len(d) < 65536:
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
            try:
                n = int(r[:i], 16)
            except ValueError:
                break
            if n == 0:
                break
            out += r[i + 2:i + 2 + n]
            r = r[i + 2 + n + 2:]
        bd = out
    return st, bd


FORM = "application/x-www-form-urlencoded"
variants = []
for n in NAMES:
    variants.append((f"{n}=<hex msgpack>", f"{n}=".encode() + BODY.hex().encode(), FORM))
for n in NAMES[:6]:
    variants.append((f"{n}=<b64 msgpack>", f"{n}=".encode() + base64.b64encode(BODY), FORM))
variants.append(("msgid+req hex", b"msgid=CMD_LOGIN&req=" + BODY.hex().encode(), FORM))
variants.append(("raw msgpack", BODY, FORM))
variants.append(("raw msgpack + ?msgid", BODY, FORM))
variants.append(("hex of hex (double)", b"req=" + BODY.hex().encode().hex().encode(), FORM))

seen = set()
for label, body, ct in variants:
    if body in seen:
        continue
    seen.add(body)
    q = "?msgid=CMD_LOGIN" if label.endswith("?msgid") else ""
    try:
        st, bd = post(PATH, body, ct, q)
    except Exception as e:
        print(f"  {label:28s} ERR {type(e).__name__}", flush=True)
        continue
    flag = "" if "500" in st else "    <<<<<< NOT 500"
    print(f"  {label:28s} {st}  {bd[:180]!r}{flag}", flush=True)
