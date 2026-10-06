#!/usr/bin/env python3
"""gate.php exists (500 on empty GET). See what it says to a POST and to a
couple of plausible bodies, so we learn the request shape it expects."""
from __future__ import annotations

import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"
PATH = "/pes22/gate.php"


def request(method: str, body: bytes, ctype: str | None) -> str:
    ctx = ssl.create_default_context()
    raw = socket.create_connection((HOST, 443), timeout=25)
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    hdrs = f"{method} {PATH} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n"
    if ctype:
        hdrs += f"Content-Type: {ctype}\r\n"
    if body:
        hdrs += f"Content-Length: {len(body)}\r\n"
    s.sendall((hdrs + "\r\n").encode() + body)
    data = b""
    while len(data) < 8192:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
    head, _, bd = data.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode("latin1", "replace") + \
        "  body=" + repr(bd[:400])


def main():
    cases = [
        ("GET", b"", None),
        ("POST", b"", "application/x-www-form-urlencoded"),
        ("POST", b"req=00", "application/x-www-form-urlencoded"),
        ("POST", b'{"CMD":"CMD_GET_SERVER_ENV"}', "application/json"),
        ("POST", b"CMD_GET_SERVER_ENV", "text/plain"),
        ("GET", b"", None),  # repeat to see if behaviour is stable
    ]
    for method, body, ctype in cases:
        tag = f"{method} {body[:50]!r}"
        try:
            print(f"  {tag}\n      {request(method, body, ctype)}", flush=True)
        except Exception as e:
            print(f"  {tag}\n      ERR {type(e).__name__}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
