#!/usr/bin/env python3
"""Probe the one absolute info URL that lives in the binary."""
from __future__ import annotations

import ssl
import socket
import sys

HOST = "info.service.konami.net"

CASES = [
    ("GET", "/XWW020-E1/info/", None),
    ("GET", "/XWW020-E1/info/index.php", None),
    ("GET", "/XWW020-E1/info/ChangeServer.bin", None),
    ("GET", "/XWW020-E1/info/getBillingPeriod", None),
    ("POST", "/XWW020-E1/info/", b""),
    ("GET", "/XWW020-E1/", None),
    ("GET", "/", None),
]


def send(method: str, path: str, body: bytes | None) -> str:
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {HOST}",
             "Connection: close"]
    if body is not None:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b""))
    data = b""
    while len(data) < 8192:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
    head, _, bd = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin1")
    return f"{status}   {head.decode('latin1').count(chr(13))} hdr lines   body={bd[:220]!r}"


def main() -> int:
    for m, p, b in CASES:
        print(f"--- {m} {p}", flush=True)
        try:
            print(f"    {send(m, p, b)}", flush=True)
        except Exception as e:
            print(f"    ERR {type(e).__name__}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
