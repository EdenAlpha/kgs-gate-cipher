#!/usr/bin/env python3
"""Dump the FULL response (status + every header + body) for gate.php.

So far we only printed the status line.  The headers tell us who is answering
(framework, cookies, waf) which is the cheapest new fact available.
"""
from __future__ import annotations

import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"


def raw(method: str, path: str, body: bytes, ctype: str | None,
        ua: bool = False) -> str:
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {HOST}",
             "Connection: close"]
    if ua:
        lines.append("User-Agent: curl/7.68.0")
    if ctype:
        lines.append(f"Content-Type: {ctype}")
        lines.append(f"Content-Length: {len(body)}")
    req = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    s.sendall(req)
    data = b""
    while len(data) < 8192:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
    head, _, bd = data.partition(b"\r\n\r\n")
    return head.decode("latin1", "replace") + f"\n    [body] {bd[:300]!r}"


CASES = [
    ("GET", "/pes22/gate.php", b"", None, False),
    ("GET", "/pes22/gate.php", b"", None, True),
    ("POST", "/pes22/gate.php", b"", "application/x-www-form-urlencoded",
     False),
    ("POST", "/pes22/gate.php", b"req=00",
     "application/x-www-form-urlencoded", True),
    ("OPTIONS", "/pes22/gate.php", b"", None, False),
    ("GET", "/pes22/nope.php", b"", None, False),
]


def main() -> int:
    for m, p, b, ct, ua in CASES:
        print(f"--- {m} {p} ua={ua} ---", flush=True)
        try:
            print(raw(m, p, b, ct, ua), flush=True)
        except Exception as e:
            print(f"    ERR {type(e).__name__}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
