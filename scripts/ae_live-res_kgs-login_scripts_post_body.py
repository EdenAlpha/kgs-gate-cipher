#!/usr/bin/env python3
"""POST the body the game produced to the endpoint the game's own composer
builds:  /pes22/gate/gate_<msgid>.php

Every byte of the payload comes from 0x767edbc (the game's serializer).
We only choose how it is wrapped.
"""
from __future__ import annotations

import ssl
import socket
import sys

HOST = "pes22-game.cs.konami.net"
BODY = open("getserverenv_body.bin", "rb").read()


def post(path, body, ctype):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    head = (f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Connection: close\r\nAccept: */*\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n")
    s.sendall(head.encode() + body)
    data = b""
    while len(data) < 262144:
        b = s.recv(8192)
        if not b:
            break
        data += b
    s.close()
    head2, _, bd = data.partition(b"\r\n\r\n")
    # de-chunk
    if b"Transfer-Encoding: chunked" in head2:
        out, rest = b"", bd
        while rest:
            i = rest.find(b"\r\n")
            if i < 0:
                break
            try:
                n = int(rest[:i], 16)
            except ValueError:
                break
            if n == 0:
                break
            out += rest[i + 2:i + 2 + n]
            rest = rest[i + 2 + n + 2:]
        bd = out
    return head2.split(b"\r\n", 1)[0].decode("latin1"), bd


def main() -> int:
    print(f"[post] game body: {len(BODY)} bytes  {BODY[:40].hex()}",
          flush=True)
    variants = [
        ("application/octet-stream", BODY),
        ("application/x-msgpack", BODY),
        ("application/msgpack", BODY),
        ("application/x-www-form-urlencoded", b"req=" + BODY.hex().encode()),
        ("application/x-www-form-urlencoded", BODY),
    ]
    for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
        path = f"/pes22/gate/gate_{msgid}.php"
        print(f"\n[post] {path}", flush=True)
        for ctype, body in variants:
            tag = ctype if not body.startswith(b"req=") else ctype + "+hex"
            if ctype.startswith("application/x-www-form") and not body.startswith(b"req="):
                tag = ctype + "+raw"
            try:
                st, bd = post(path, body, ctype)
            except Exception as e:
                print(f"   {tag:42s} ERR {e}", flush=True)
                continue
            print(f"   {tag:42s} {st}  {bd[:300]!r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
