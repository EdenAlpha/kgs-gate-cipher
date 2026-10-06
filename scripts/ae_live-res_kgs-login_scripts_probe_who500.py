#!/usr/bin/env python3
"""WHO returns the 500?  Full response headers + server timing.

nginx, php-fpm, an ALB and an ELB each announce themselves differently.  If
the 500 carries an AWS signature (awselb, Server: AWS, x-amzn-RequestId) it is
a load balancer with an unhealthy target -- i.e. the backend is down and no
request we can craft will change the answer.

Also measures time-to-first-byte so we can tell a local nginx error from a
proxy that waited on a dead upstream.
"""
from __future__ import annotations

import socket
import ssl
import time

TARGETS = [
    ("gate 500", "pes22-game.cs.konami.net",
     "POST", "/pes22/gate/gate_CMD_LOGIN.php", True),
    ("gate GET", "pes22-game.cs.konami.net",
     "GET", "/pes22/gate/gate_CMD_LOGIN.php", False),
    ("gate req=", "pes22-game.cs.konami.net",
     "POST", "/pes22/gate/gate_CMD_LOGIN.php", "form"),
    ("gate info (working control)", "ntl.service.konami.net",
     "POST", "/ntl/api/GateInfo.php", True),
    ("gate nginx 403", "pes22-game.cs.konami.net",
     "GET", "/pes22/gate/", False),
]

FORM = b"req=" + (
    b"%7B%22msgid%22%3A%22CMD_LOGIN%22%2C%22client_version%22%3A%226.1.0%22%7D")
MSGPACK = (b"\x8a\xa5msgid\xa9CMD_LOGIN\xa4rqid\x00\xa7user_id\x00"
           b"\xaasession_id\xa0\xabmy_platform\xa0\xa9s_keyword\xa0"
           b"\xa4lang\xa3en\xa6region\xa0\xa8platform\xa0"
           b"\xaeclient_version\xa0")


def main() -> int:
    for label, host, method, path, payload in TARGETS:
        if payload is True:
            body, ct = MSGPACK, "application/x-www-form-urlencoded"
        elif payload == "form":
            body, ct = FORM, "application/x-www-form-urlencoded"
        else:
            body, ct = b"", None
        ip = socket.gethostbyname(host)
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        print("=" * 72)
        print("%s  %s %s@%s" % (label, method, path, host))
        try:
            t0 = time.time()
            with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=12),
                                 server_hostname=host) as s:
                s.settimeout(15)
                hdr = ("%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, host))
                if body:
                    hdr += ("Content-Type: %s\r\nContent-Length: %d\r\n"
                            % (ct, len(body)))
                hdr += "Connection: close\r\n\r\n"
                s.sendall(hdr.encode() + body)
                d = b""
                first = None
                while len(d) < 4000:
                    b = s.recv(2000)
                    if not b:
                        break
                    if first is None:
                        first = time.time()
                    d += b
            print("  ip=%s  TTFB=%.3fs  total=%.3fs"
                  % (ip, (first or time.time()) - t0,
                     time.time() - t0))
            head = d.partition(b"\r\n\r\n")[0].decode("latin1")
            for line in head.split("\r\n"):
                print("    " + line)
            print("    [body] %r" % d.partition(b"\r\n\r\n")[2][:160])
        except Exception as e:
            print("  ERR %s: %s" % (type(e).__name__, str(e)[:120]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
