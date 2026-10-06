#!/usr/bin/env python3
"""Konami's PHP APIs take JSON hex-encoded in a form field.

GateInfo (seen in plaintext in the capture):
    POST /ntl/api/GateInfo.php
    Content-Type: application/x-www-form-urlencoded
    req=7b227469746c65436f6465...      <- hex of {"titleCode":...}

So the gate very likely wants the same convention: req=<hex(JSON)>.
We have been sending raw MessagePack instead.  Test JSON in every plausible
wrapping.
"""
from __future__ import annotations

import json
import socket
import ssl

HOST = "pes22-game.cs.konami.net"
FORM = "application/x-www-form-urlencoded"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"

# the exact fields the game's own serializer produces, as JSON
ENVELOPE = [
    ("msgid", "CMD_GET_SERVER_ENV"),
    ("rqid", 1),
    ("user_id", 0),
    ("session_id", ""),
    ("my_platform", ""),
    ("s_keyword", ""),
    ("lang", "en"),
    ("region", "US"),
    ("platform", "PES"),
    ("client_version", "6.0.1"),
]


def json_for(msgid):
    d = []
    for k, v in ENVELOPE:
        if k == "msgid":
            d.append((k, msgid))
        else:
            d.append((k, v))
    return json.dumps(dict(d), separators=(",", ":")).encode()


def post(path, body, ct, ua=UA, extra=()):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    L = [f"POST {path} HTTP/1.1", f"Host: {HOST}", f"User-Agent: {ua}",
         "Accept: */*", "Connection: close"]
    if ct:
        L.append("Content-Type: " + ct)
    for e in extra:
        L.append(e)
    L.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    s.settimeout(25)
    d = b""
    while len(d) < 65536:
        b = s.recv(8192)
        if not b:
            break
        d += b
    s.close()
    st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return st, d.partition(b"\r\n\r\n")[2]


for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
    path = f"/pes22/gate/gate_{msgid}.php"
    js = json_for(msgid)
    hexjs = js.hex().encode()
    print(f"=== {path}")
    print(f"    json = {js.decode()}")
    cases = [
        ("req=<hex(json)>", b"req=" + hexjs, FORM),
        ("raw json", js, "application/json"),
        ("dat=<hex(json)>", b"dat=" + hexjs, FORM),
        ("req=<plain json>", b"req=" + js, FORM),
        ("json field named msgid", msgid.encode() + b"=" + hexjs, FORM),
        ("raw json / form CT", js, FORM),
        ("msg=<hex(json)>", b"msg=" + hexjs, FORM),
    ]
    for label, b, ct in cases:
        try:
            st, bd = post(path, b, ct)
        except Exception as e:
            print(f"    {label:24s} ERR {type(e).__name__}: {e}")
            continue
        flag = "    <<<<<< NOT A BLANK 500" if (bd and bd not in (b"", b"0\r\n\r\n")) or "500" not in st else ""
        print(f"    {label:24s} {st}  {bd[:200]!r}{flag}")
    print()
