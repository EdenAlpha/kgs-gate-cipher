#!/usr/bin/env python3
"""Test gate.php with the envelope Konami demonstrably uses elsewhere.

GateInfo.php answered 200 to:  req=<lowercase-hex of the JSON>

If the command front controller uses the same convention, a well-formed
envelope should stop returning the bare 500 and start talking.
"""
from __future__ import annotations

import json
import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"
PATH = "/pes22/gate.php"


def request(body: bytes, ctype: str, method: str = "POST") -> str:
    ctx = ssl.create_default_context()
    raw = socket.create_connection((HOST, 443), timeout=25)
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    hdrs = (f"{method} {PATH} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Connection: close\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n")
    s.sendall(hdrs.encode() + body)
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


def main() -> int:
    payload = {"CMD": "CMD_GET_SERVER_ENV"}
    hexed = json.dumps(payload, separators=(",", ":")).encode().hex()

    cases = [
        (f"req={hexed}".encode(), "application/x-www-form-urlencoded",
         "req=hex (GateInfo convention)"),
        (f"cmd=CMD_GET_SERVER_ENV".encode(),
         "application/x-www-form-urlencoded", "cmd=NAME"),
        (json.dumps(payload, separators=(",", ":")).encode(),
         "application/json", "json object"),
    ]
    for body, ctype, tag in cases:
        try:
            print(f"  {tag}\n      {request(body, ctype)}", flush=True)
        except Exception as e:
            print(f"  {tag}\n      ERR {type(e).__name__}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
