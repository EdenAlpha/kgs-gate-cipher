#!/usr/bin/env python3
"""Is the whole gate docroot broken, or only the scripts we chose?

Three cheap discriminating checks:
  1. port 80 on pes22-game (nobody has ever tested it -- GateInfo works on
     port 80, and the app's own captures show TCP 80 traffic to game hosts)
  2. a script that must exist for nginx to work at all (index.php)
  3. whether a DIFFERENT Host header gets a different answer (i.e. is this a
     shared nginx whose default vhost we are landing on?)
"""
from __future__ import annotations

import socket
import ssl

HOST = "pes22-game.cs.konami.net"

CASES = [
    # (label, port, tls, host_header, request)
    ("p80 GET  /", 80, False, HOST, "GET / HTTP/1.1"),
    ("p80 GET  /pes22/gate/", 80, False, HOST, "GET /pes22/gate/ HTTP/1.1"),
    ("p80 POST gate_CMD_LOGIN", 80, False, HOST,
     "POST /pes22/gate/gate_CMD_LOGIN.php HTTP/1.1"),
    ("p443 GET  /index.php", 443, True, HOST,
     "GET /pes22/gate/index.php HTTP/1.1"),
    ("p443 GET  /index.php (root)", 443, True, HOST,
     "GET /index.php HTTP/1.1"),
    ("p443 POST gate (Host: default)", 443, True, "example.com",
     "POST /pes22/gate/gate_CMD_LOGIN.php HTTP/1.1"),
    ("p443 GET  /robots.txt", 443, True, HOST,
     "GET /robots.txt HTTP/1.1"),
    ("p443 GET  /favicon.ico", 443, True, HOST,
     "GET /favicon.ico HTTP/1.1"),
]

MSGPACK = (b"\x8a\xa5msgid\xa9CMD_LOGIN\xa4rqid\x00\xa7user_id\x00"
           b"\xaasession_id\xa0\xabmy_platform\xa0\xa9s_keyword\xa0"
           b"\xa4lang\xa3en\xa6region\xa0\xa8platform\xa0"
           b"\xaeclient_version\xa0")


def main() -> int:
    ip = socket.gethostbyname(HOST)
    print("resolved %s -> %s\n" % (HOST, ip), flush=True)
    for label, port, tls, host, req in CASES:
        try:
            raw = socket.create_connection((ip, port), timeout=10)
            s = raw
            if tls:
                ctx = ssl.create_default_context()
                ctx.set_alpn_protocols(["http/1.1"])
                s = ctx.wrap_socket(raw, server_hostname=HOST)
            s.settimeout(12)
            body = MSGPACK if req.startswith("POST") else b""
            hdr = req + "\r\nHost: %s\r\n" % host
            if body:
                hdr += ("Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: %d\r\n" % len(body))
            hdr += "Connection: close\r\n\r\n"
            s.sendall(hdr.encode() + body)
            d = b""
            while len(d) < 3000:
                b = s.recv(1500)
                if not b:
                    break
                d += b
            s.close()
            line = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
            print("  %-32s -> %s" % (label, line), flush=True)
            head = d.partition(b"\r\n\r\n")[0].decode("latin1")
            extra = [l for l in head.split("\r\n")[1:]
                     if l.lower().startswith(("server:", "x-powered",
                                              "location", "set-cookie"))]
            if extra:
                print("      " + " | ".join(extra), flush=True)
            print("      body=%r" % d.partition(b"\r\n\r\n")[2][:70],
                  flush=True)
        except Exception as e:
            print("  %-32s -> ERR %s: %s"
                  % (label, type(e).__name__, str(e)[:80]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
