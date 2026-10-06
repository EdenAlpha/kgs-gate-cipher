#!/usr/bin/env python3
"""Does the gate reject our request because of EMPTY/placeholder fields?

Every attempt so far sent the game's own MessagePack body with
`lang/region/platform/client_version` left as `NotImplement` or empty, because
that is how the ctor serialises an uninitialised command object.  A PHP router
that fatal-errors on a missing/short `client_version` would return exactly what
we see: HTTP 500, empty body, in ~60 ms.

So: take the GAME'S OWN serialised bytes, change only the values, re-encode,
and see whether any input stops returning 500.
"""
from __future__ import annotations

import json
import os
import socket
import ssl

import msgpack

HOST = "pes22-game.cs.konami.net"
MSGID = "CMD_GET_SERVER_ENV"
PATH = "/pes22/gate/gate_CMD_%s.php" % MSGID

HERE = os.path.dirname(os.path.abspath(__file__))

# the game's own bytes, captured from its own serializer (drive_cmd_wire.py)
GAME_BODY = (b"\x8a\xa5msgid\xb2CMD_GET_SERVER_ENV\xa4rqid\x00\xa7user_id"
             b"\x00\xaasession_id\xa0\xabmy_platform\xa0\xa9s_keyword"
             b"\xa0\xa4lang\xa3E}\t\xa6region\xa0\xa8platform\xa0"
             b"\xaeclient_version\xa0")

VARIANTS = [
    ("game bytes as-is", {}),
    ("version dt270", {"client_version": "dt270"}),
    ("version 5.5.1", {"client_version": "5.5.1"}),
    ("version 6.1.0", {"client_version": "6.1.0"}),
    ("version 6.0.0", {"client_version": "6.0.0"}),
    ("full plausible", {"client_version": "6.1.0", "lang": "en",
                        "region": "US", "platform": "Android",
                        "my_platform": "Android", "s_keyword": "",
                        "user_id": "00fcb5c1", "session_id": ""}),
    ("full + version dt270", {"client_version": "dt270", "lang": "en",
                              "region": "US", "platform": "Android",
                              "my_platform": "Android"}),
    ("empty map", None),
    ("json instead of msgpack",
     {"__json__": '{"msgid":"CMD_GET_SERVER_ENV","client_version":"6.1.0"}'}),
]


def send(path, body, content_type="application/x-www-form-urlencoded", ip=None):
    host = HOST
    ip = ip or socket.gethostbyname(host)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=12),
                         server_hostname=host) as s:
        req = ("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n"
               % (path, host, content_type, len(body))).encode()
        s.sendall(req + body)
        s.settimeout(15)
        d = b""
        while len(d) < 8000:
            b = s.recv(4096)
            if not b:
                break
            d += b
    line = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return line, d.partition(b"\r\n\r\n")[2][:120]


def main() -> int:
    ip = socket.gethostbyname(HOST)
    print("host %s -> %s" % (HOST, ip), flush=True)
    for label, changes in VARIANTS:
        ct = "application/x-www-form-urlencoded"
        if changes is None:
            body, path = json.dumps({"msgid": MSGID}).encode(), PATH
        elif "__json__" in changes:
            body, ct = changes["__json__"].encode(), "application/json"
            path = PATH
        else:
            d = msgpack.unpackb(GAME_BODY, raw=False)
            d.update(changes)
            body, path = msgpack.packb(d, use_bin_type=True), PATH
        try:
            line, b = send(path, body, ct, ip)
        except Exception as e:
            line, b = "ERR %s: %s" % (type(e).__name__, str(e)[:70]), b""
        print("  %-24s %d B -> %s  %r" % (label, len(body), line, b),
              flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
