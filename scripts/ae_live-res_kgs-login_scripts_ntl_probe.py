#!/usr/bin/env python3
"""The ntl host is the ONE Konami host that answers us (GateInfo -> 200).

If the gate scripts were ever mirrored there -- or if the guest-login token
endpoint lives there -- a 404/405/500 difference from the control will show
it.  Cheap negative-or-jackpot probe: candidate script names on the working
host, GET and POST, with a real msgpack body.
"""
from __future__ import annotations

import socket
import ssl

HOST = "ntl.service.konami.net"
CONTROL = "/ntl/api/GateInfo.php"

CANDIDATES = [
    CONTROL,
    "/ntl/api/CmdGetServerEnv.php",
    "/ntl/api/CmdLogin.php",
    "/ntl/api/CmdGetKgsGuestLoginToken.php",
    "/ntl/api/gate_CMD_GET_SERVER_ENV.php",
    "/ntl/api/gate_CMD_LOGIN.php",
    "/ntl/api/GetKgsGuestLoginToken.php",
    "/ntl/api/general/ReportLog.php",
    "/ntl/api/GateInfo.php/x",
    "/ntl/gate/gate_CMD_LOGIN.php",
    "/gate/gate_CMD_LOGIN.php",
    "/pes22/gate/gate_CMD_LOGIN.php",
]

BODY = (b"\x8a\xa5msgid\xa9CMD_LOGIN\xa4rqid\x00\xa7user_id\x00"
        b"\xaasession_id\xa0\xabmy_platform\xa0\xa9s_keyword\xa0"
        b"\xa4lang\xa3en\xa6region\xa0\xa8platform\xa0"
        b"\xaeclient_version\xa0")


def go(ip, path, method):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    body = BODY if method == "POST" else b""
    with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=10),
                         server_hostname=HOST) as s:
        s.settimeout(12)
        hdr = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, HOST)
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
    line = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return line, d.partition(b"\r\n\r\n")[2][:70]


def main() -> int:
    ip = socket.gethostbyname(HOST)
    print("%s -> %s" % (HOST, ip), flush=True)
    for path in CANDIDATES:
        for method in ("GET", "POST"):
            try:
                line, body = go(ip, path, method)
            except Exception as e:
                line, body = "ERR %s: %s" % (type(e).__name__,
                                             str(e)[:60]), b""
            print("  %-4s %-42s %-34s %r" % (method, path, line, body),
                  flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
