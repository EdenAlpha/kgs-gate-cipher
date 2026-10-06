#!/usr/bin/env python3
"""Retry the gate POST with the User-Agent the game itself builds."""
from __future__ import annotations

import socket
import ssl

HOST = "pes22-game.cs.konami.net"
BODY = open("getserverenv_body.bin", "rb").read()
UA = open("game_user_agent.txt").read().strip()
print("UA =", UA)


def post(path, body, ct, ua=UA, extra=()):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=20),
                        server_hostname=HOST)
    L = ["POST %s HTTP/1.1" % path, "Host: " + HOST, "User-Agent: " + ua,
         "Accept: */*", "Connection: close"]
    if ct:
        L.append("Content-Type: " + ct)
    for e in extra:
        L.append(e)
    L.append("Content-Length: %d" % len(body))
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
    return st + " | " + repr(d.partition(b"\r\n\r\n")[2][:200])


CASES = [
    ("form CT + raw msgpack", BODY, "application/x-www-form-urlencoded", ()),
    ("octet-stream + raw", BODY, "application/octet-stream", ()),
    ("form CT + req=<hex>", b"req=" + BODY.hex().encode(),
     "application/x-www-form-urlencoded", ()),
    ("soap CT + raw", BODY, 'text/xml; charset="utf-8"', ()),
    ("no CT + raw", BODY, None, ()),
    ("x-msgpack + raw", BODY, "application/x-msgpack", ()),
]

for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
    p = "/pes22/gate/gate_%s.php" % msgid
    print("==", p)
    for label, body, ct, extra in CASES:
        try:
            print("  %-24s %s" % (label, post(p, body, ct, extra=extra)))
        except Exception as e:
            print("  %-24s ERR %s: %s" % (label, type(e).__name__, e))
