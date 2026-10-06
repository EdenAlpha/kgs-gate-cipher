#!/usr/bin/env python3
"""Is the gate fatal because `req` is missing?

Evidence stack:
  * php-fpm is alive: /index.php -> 404 "File not found."
  * gate_CMD_LOGIN.php exists and returns 500 for GET, raw msgpack, and form
    input alike -- in a flat 0.24 s with an empty body.
  * the one working Konami script (GateInfo) reads a FORM FIELD called `req`
    containing url-encoded JSON:  req=7b227469746c65436f646522...

A PHP 8 script that does `$d = json_decode($_POST['req'])` and then touches
`$d['msgid']` fatals exactly like this when `req` is absent (null deref ->
500, display_errors off -> empty body).  It would do that for a raw-msgpack
POST and for a GET too -- which is what we observe.

So: send `req=` in every plausible encoding and see if any stops 500'ing.
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.parse

HOST = "pes22-game.cs.konami.net"
PATH = "/pes22/gate/gate_CMD_LOGIN.php"

MSGPACK = (b"\x8a\xa5msgid\xa9CMD_LOGIN\xa4rqid\x00\xa7user_id\x00"
           b"\xaasession_id\xa0\xabmy_platform\xa0\xa9s_keyword\xa0"
           b"\xa4lang\xa3en\xa6region\xa0\xa8platform\xa0"
           b"\xaeclient_version\xa0")

JSON_FULL = {"msgid": "CMD_LOGIN", "rqid": "", "user_id": "",
             "session_id": "", "my_platform": "Android", "s_keyword": "",
             "lang": "en", "region": "US", "platform": "Android",
             "client_version": "11.0.1"}

JSON_MIN = {"msgid": "CMD_LOGIN"}
JSON_REAL = {"titleCode": "pes22", "locale": "en", "version": "dt270",
             "extra": "", "apiLevel": "4"}


def enc(d):
    return json.dumps(d, separators=(",", ":")).encode()


CASES = [
    ("req= msgpack (urlenc)", PATH,
     "application/x-www-form-urlencoded",
     b"req=" + urllib.parse.quote_from_bytes(MSGPACK).encode()),
    ("req= json (full)", PATH, "application/x-www-form-urlencoded",
     b"req=" + enc(JSON_FULL)),
    ("req= json (msgid only)", PATH, "application/x-www-form-urlencoded",
     b"req=" + enc(JSON_MIN)),
    ("req= json (GateInfo shape)", PATH, "application/x-www-form-urlencoded",
     b"req=" + enc(JSON_REAL)),
    ("req= empty", PATH, "application/x-www-form-urlencoded", b"req="),
    ("query ?msgid=CMD_LOGIN", PATH + "?msgid=CMD_LOGIN",
     None, b""),
    ("raw msgpack (control)", PATH,
     "application/x-www-form-urlencoded", MSGPACK),
    ("body= json, app/json", PATH, "application/json", enc(JSON_FULL)),
    ("data= json", PATH, "application/x-www-form-urlencoded",
     b"data=" + enc(JSON_FULL)),
    ("req= msgpack+b64", PATH, "application/x-www-form-urlencoded",
     b"req=" + __import__("base64").b64encode(MSGPACK)),
]

# same matrix against the OTHER script, to see whether the crash is
# per-script or universal
CASES += [
    ("[ENV] req= json (full)", "/pes22/gate/gate_CMD_GET_SERVER_ENV.php",
     "application/x-www-form-urlencoded", b"req=" + enc(JSON_FULL)),
    ("[ENV] raw msgpack (control)",
     "/pes22/gate/gate_CMD_GET_SERVER_ENV.php",
     "application/x-www-form-urlencoded", MSGPACK),
]


def main() -> int:
    ip = socket.gethostbyname(HOST)
    print("resolved %s -> %s\n" % (HOST, ip), flush=True)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    for label, path, ct, body in CASES:
        try:
            with ctx.wrap_socket(socket.create_connection((ip, 443),
                                                          timeout=10),
                                 server_hostname=HOST) as s:
                s.settimeout(12)
                hdr = "POST %s HTTP/1.1\r\nHost: %s\r\n" % (path, HOST)
                if ct:
                    hdr += "Content-Type: %s\r\n" % ct
                hdr += ("Content-Length: %d\r\nConnection: close\r\n\r\n"
                        % len(body))
                s.sendall(hdr.encode() + body)
                d = b""
                while len(d) < 4000:
                    b = s.recv(2000)
                    if not b:
                        break
                    d += b
            line = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
            print("  %-30s -> %-32s %r"
                  % (label, line, d.partition(b"\r\n\r\n")[2][:80]),
                  flush=True)
        except Exception as e:
            print("  %-30s -> ERR %s: %s"
                  % (label, type(e).__name__, str(e)[:70]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
