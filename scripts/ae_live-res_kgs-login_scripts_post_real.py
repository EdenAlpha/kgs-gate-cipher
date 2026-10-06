#!/usr/bin/env python3
"""POST the corrected body (real lang/region/platform/version) to the gate.

The earlier body carried "NotImplement" placeholders because the field
binder never ran.  This one carries what the app actually sends.
"""
from __future__ import annotations

import socket
import ssl

HOST = "pes22-game.cs.konami.net"
FORM = "application/x-www-form-urlencoded"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
BODY = open("real_body.bin", "rb").read()
print(f"body {len(BODY)}B  {BODY.hex()}\n")


def post(path, body, ct, ua=UA):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    L = [f"POST {path} HTTP/1.1", f"Host: {HOST}", f"User-Agent: {ua}",
         "Accept: */*", "Connection: close"]
    if ct:
        L.append("Content-Type: " + ct)
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


CASES = [
    ("raw msgpack / form CT", BODY, FORM),
    ("req=<hex>", b"req=" + BODY.hex().encode(), FORM),
    ("octet-stream", BODY, "application/octet-stream"),
    ("x-msgpack", BODY, "application/x-msgpack"),
]

for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
    path = f"/pes22/gate/gate_{msgid}.php"
    print("===", path)
    for label, b, ct in CASES:
        try:
            st, bd = post(path, b, ct)
        except Exception as e:
            print(f"  {label:24s} ERR {type(e).__name__}: {e}")
            continue
        flag = "   <<<<<< DIFFERENT!" if "500" not in st else ""
        print(f"  {label:24s} {st}  {bd[:240]!r}{flag}")
    print()
