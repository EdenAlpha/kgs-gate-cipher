#!/usr/bin/env python3
"""Are the eight current IPs of pes22-game identical?

Today DNS hands out a rotating set of addresses.  One of them just answered
404 "File not found." (nginx/fastcgi: script absent) where earlier probes on
other addresses returned 500 (php: script ran and died).  Those are different
server states -- so at least one address is NOT the same front end.

For every address: POST two real script names and a bare GET, and print what
came back.  A 200 anywhere is the endpoint that actually works.
"""
from __future__ import annotations

import socket
import ssl

HOST = "pes22-game.cs.konami.net"
SCRIPTS = [
    ("POST", "/pes22/gate/gate_CMD_GET_SERVER_ENV.php", b"\x8a\xa5msgid"
     b"\xb2CMD_GET_SERVER_ENV\xa4rqid\x00\xa7user_id\x00\xaasession_id"
     b"\xa0\xabmy_platform\xa0\xa9s_keyword\xa0\xa4lang\xa3en\xa6region"
     b"\xa0\xa8platform\xa0\xaeclient_version\xa0"),
    ("POST", "/pes22/gate/gate_CMD_LOGIN.php", b"\x8a\xa5msgid\xa9"
     b"CMD_LOGIN\xa4rqid\x00\xa7user_id\x00\xaasession_id\xa0\xab"
     b"my_platform\xa0\xa9s_keyword\xa0\xa4lang\xa3en\xa6region\xa0"
     b"\xa8platform\xa0\xaeclient_version\xa0"),
    ("GET", "/", b""),
    ("GET", "/pes22/gate/", b""),
]


def main() -> int:
    try:
        infos = socket.getaddrinfo(HOST, 443, socket.AF_INET,
                                   socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
    except Exception as e:
        print("resolve failed:", e)
        return 1
    print("resolved %d addresses: %s" % (len(ips), " ".join(ips)), flush=True)

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])

    for ip in ips:
        print("\n== %s ==" % ip, flush=True)
        for method, path, body in SCRIPTS:
            try:
                with ctx.wrap_socket(
                        socket.create_connection((ip, 443), timeout=10),
                        server_hostname=HOST) as s:
                    hdr = ("%s %s HTTP/1.1\r\nHost: %s\r\n" %
                           (method, path, HOST))
                    if body:
                        hdr += ("Content-Type: "
                                "application/x-www-form-urlencoded\r\n"
                                "Content-Length: %d\r\n" % len(body))
                    hdr += "Connection: close\r\n\r\n"
                    s.settimeout(12)
                    s.sendall(hdr.encode() + body)
                    d = b""
                    while len(d) < 6000:
                        b = s.recv(3000)
                        if not b:
                            break
                        d += b
                line = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
                payload = d.partition(b"\r\n\r\n")[2][:90]
                print("   %-5s %-40s %-26s %r"
                      % (method, path.split("/")[-1] or "/", line, payload),
                      flush=True)
            except Exception as e:
                print("   %-5s %-40s ERR %s: %s"
                      % (method, path, type(e).__name__, str(e)[:70]),
                      flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
