#!/usr/bin/env python3
"""Plain reachability probe of the command server (own TLS, not the game's)."""
from __future__ import annotations

import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"
PATHS = [
    "/",
    "/pes22/",
    "/pes22/gate/",
    "/pes22/CmdGetServerEnv.php",
    "/pes22/gate/CmdGetServerEnv.php",
    "/pes22/gate/gate_CmdGetServerEnv.php",
    "/pes22/gate.php",
]


def main():
    ctx = ssl.create_default_context()
    for p in PATHS:
        try:
            raw = socket.create_connection((HOST, 443), timeout=20)
            s = ctx.wrap_socket(raw, server_hostname=HOST)
            s.sendall(
                f"GET {p} HTTP/1.1\r\nHost: {HOST}\r\n"
                f"Connection: close\r\n\r\n".encode()
            )
            data = b""
            while len(data) < 8192:
                b = s.recv(4096)
                if not b:
                    break
                data += b
            s.close()
            head, _, body = data.partition(b"\r\n\r\n")
            status = head.split(b"\r\n")[0].decode("latin1", "replace")
            print(f"  {p}\n      {status}  body={body[:100]!r}", flush=True)
        except Exception as e:
            print(f"  {p}\n      ERR {type(e).__name__}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
