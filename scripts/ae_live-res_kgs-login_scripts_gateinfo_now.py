#!/usr/bin/env python3
"""Read the game's live endpoint config from GateInfo.php (works from here).

Byte-for-byte the request the working app sent in the user's capture (2026-09-28):
    POST /ntl/api/GateInfo.php   req=<HEX of JSON>
    {"titleCode":"PES2022","locale":"US","version":"6.0.1","extra":"","apiLevel":"4"}

If the response now carries a NEW game endpoint, the app is talking to a host
we have never probed -- which would fully explain "phone works, this box can't".
"""
from __future__ import annotations

import json
import socket

HOST = "ntl.service.konami.net"
PATH = "/ntl/api/GateInfo.php"

D = {"titleCode": "PES2022", "locale": "US", "version": "6.0.1",
     "extra": "", "apiLevel": "4"}
BODY = b"req=" + json.dumps(D, separators=(",", ":")).encode().hex().encode()


def main() -> int:
    ip = socket.gethostbyname(HOST)
    s = socket.create_connection((ip, 80), timeout=12)
    s.settimeout(15)
    req = ("POST %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n"
           "Content-Length: %d\r\nContent-Type: application/"
           "x-www-form-urlencoded\r\nConnection: close\r\n\r\n"
           % (PATH, HOST, len(BODY))).encode()
    s.sendall(req + BODY)
    d = b""
    while len(d) < 8000:
        b = s.recv(4000)
        if not b:
            break
        d += b
    s.close()
    print(d.decode("latin1", "replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
