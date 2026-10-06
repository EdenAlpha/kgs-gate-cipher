#!/usr/bin/env python3
"""Probe gate/gate_<a>.php where <a> comes from the API-name table at
0x7b02148 (ApiManager / CommandApi / LowCommandApi / DlToMemApi /
DlToStorageApi / UploadApi).  These names are read out of the binary, not
invented.
"""
from __future__ import annotations

import ssl
import socket
import sys

HOST = "pes22-game.cs.konami.net"

NAMES = [
    "CommandApi", "LowCommandApi", "DlToMemApi", "DlToStorageApi",
    "UploadApi", "ApiManager",
    "commandapi", "lowcommandapi", "dltomemapi", "dltostrageapi",
    "dltostorageapi", "uploadapi", "apimanager",
    "COMMAND_API", "command_api", "COMMAND", "command",
    "Api", "api",
]


def get(path, method="GET", body=None, ctype=None):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {HOST}",
             "Connection: close", "Accept: */*"]
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
    return head.split(b"\r\n", 1)[0].decode("latin1"), bd


def main() -> int:
    for n in NAMES:
        p = f"/pes22/gate/gate_{n}.php"
        try:
            st, bd = get(p)
        except Exception as e:
            print(f"{p:52s} ERR {e}", flush=True)
            continue
        mark = "" if "404" in st else "   <<<<<<"
        print(f"{p:52s} {st}  {bd[:160]!r}{mark}", flush=True)
        if "404" not in st:
            # if it exists, try POST with the game-produced body
            body = open("getserverenv_body.bin", "rb").read()
            try:
                st2, bd2 = get(p, "POST", body,
                               "application/octet-stream")
                print(f"    POST -> {st2}  {bd2[:400]!r}", flush=True)
            except Exception as e:
                print(f"    POST -> ERR {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
