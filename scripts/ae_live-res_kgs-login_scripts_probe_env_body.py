#!/usr/bin/env python3
"""Send the body the game itself produced to the endpoint the game itself chose.

The bytes come from 0x767eaf0 + 0x767edbc (run under Unicorn); the URL comes
from get_endpoint_config + composer.  Nothing here is hand-written.
"""
from __future__ import annotations

import os
import ssl
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BODY = open(os.path.join(HERE, "getserverenv_body.bin"), "rb").read()

HOST = "pes22-game.cs.konami.net"
PATH = "/pes22/gate.php"

CASES = [
    ("POST", PATH, BODY, "application/octet-stream", "raw msgpack"),
    ("POST", PATH, BODY, "application/x-msgpack", "raw msgpack (x-msgpack)"),
    ("POST", PATH, BODY, "application/msgpack", "raw msgpack (msgpack)"),
    ("POST", PATH, BODY, "application/x-www-form-urlencoded", "raw as form"),
    ("POST", PATH, b"req=" + BODY.hex().encode(),
     "application/x-www-form-urlencoded", "req=<hex> form"),
    ("POST", PATH, b"req=" + BODY.hex().encode(),
     "application/octet-stream", "req=<hex> octet"),
    ("GET", PATH + "?req=" + BODY.hex(), None, None, "GET req=<hex>"),
]


def send(method, path, body, ctype):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {HOST}",
             "Connection: close", "Accept: */*",
             "User-Agent: okhttp/3.12.1"]
    if body is not None:
        lines.append(f"Content-Type: {ctype}")
        lines.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b""))
    data = b""
    while len(data) < 65536:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
    head, _, bd = data.partition(b"\r\n\r\n")
    return head.split(b"\r\n", 1)[0].decode("latin1"), head, bd


def main() -> int:
    print(f"body = {len(BODY)} bytes", flush=True)
    print(f"head = {BODY[:60]!r}", flush=True)
    for method, path, body, ctype, label in CASES:
        print(f"--- {label}", flush=True)
        try:
            status, head, bd = send(method, path, body, ctype)
            print(f"    {status}", flush=True)
            if bd or b"500" not in status.encode():
                print(f"    hdrs: {head.decode('latin1')[:400]!r}", flush=True)
                print(f"    body: {bd[:600]!r}", flush=True)
        except Exception as e:
            print(f"    ERR {type(e).__name__}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
