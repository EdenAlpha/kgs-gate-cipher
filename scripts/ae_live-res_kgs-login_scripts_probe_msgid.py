#!/usr/bin/env python3
"""a in gate/gate_<a>.php is the msgid (CMD_XXX), not the script filename.

  * GET every CMD_* literal the binary contains + a bogus control
  * then POST the body the game itself produced to the live ones
"""
from __future__ import annotations

import re
import ssl
import socket
import sys

HOST = "pes22-game.cs.konami.net"
SO = r"apk_lab\libUE4.so"


def get(path, method="GET", body=None, ctype=None):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {HOST}",
             "Connection: close", "Accept: */*"]
    if body is not None:
        lines.append("Content-Type: " + (ctype or "application/octet-stream"))
        lines.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b""))
    data = b""
    while len(data) < 262144:
        b = s.recv(8192)
        if not b:
            break
        data += b
    s.close()
    head, _, bd = data.partition(b"\r\n\r\n")
    return head.split(b"\r\n", 1)[0].decode("latin1"), bd


def main() -> int:
    data = open(SO, "rb").read()
    names = sorted({m.group(0).decode()
                    for m in re.finditer(rb"CMD_[A-Z][A-Z0-9_]{2,60}", data)})
    print(f"[msg] {len(names)} CMD_* literals in the binary", flush=True)

    control = ["CMD_BOGUS_DOES_NOT_EXIST", "CMD_"]
    live = []
    for n in control + names:
        p = f"/pes22/gate/gate_{n}.php"
        try:
            st, bd = get(p)
        except Exception as e:
            print(f"  {n:40s} ERR {e}", flush=True)
            continue
        mark = "" if "404" in st else "   <<<<<<"
        print(f"  {n:40s} {st}  {bd[:70]!r}{mark}", flush=True)
        if "404" not in st:
            live.append((n, st, bd))

    print(f"\n[msg] live = {[n for n, _, _ in live]}", flush=True)

    # ---- now POST the body the game produced --------------------------
    try:
        body = open("getserverenv_body.bin", "rb").read()
    except Exception as e:
        print(f"[msg] no body: {e}", flush=True)
        return 0
    print(f"[msg] posting {len(body)}-byte game body", flush=True)
    for n, st, _ in live:
        for ctype in ("application/x-msgpack", "application/octet-stream",
                      "application/msgpack", "text/plain"):
            try:
                st2, bd = get(f"/pes22/gate/gate_{n}.php", "POST", body, ctype)
            except Exception as e:
                print(f"  POST {n} {ctype}: ERR {e}", flush=True)
                continue
            print(f"  POST {n:34s} {ctype:26s} {st2}  {bd[:160]!r}",
                  flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
