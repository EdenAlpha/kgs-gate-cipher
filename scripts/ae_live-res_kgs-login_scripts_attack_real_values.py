#!/usr/bin/env python3
"""Direct attack: the values the WORKING app sends, in the shapes it uses.

Everything below comes from plaintext bytes in the user's own capture
(passthrough_capture.csv), not from guesses:
  version/client_version = "6.0.1"      titleCode = PES2022   locale = US
  uid = 3c5aad3c6b8425c611ebe2f5da6c25af
  libVer = 1.17.1-Android-15            opt = 22011111
  ReportLog lives at /ntl/api/PES2022/ReportLog.php  (titleCode directory!)

So we try, on both hosts, the titleCode-directory paths we never tried and the
real client_version we never sent.
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.parse

import msgpack

UID = "3c5aad3c6b8425c611ebe2f5da6c25af"
VER = "6.0.1"

TLS_HOST = "pes22-game.cs.konami.net"
HTTP_HOST = "ntljp.service.konami.net"

PATHS_TLS = [
    "/pes22/gate/gate_CMD_GET_SERVER_ENV.php",
    "/pes22/gate/gate_CMD_LOGIN.php",
    "/PES2022/gate/gate_CMD_GET_SERVER_ENV.php",
    "/PES2022/gate/gate_CMD_LOGIN.php",
]
PATHS_HTTP = [
    "/ntl/api/PES2022/gate_CMD_GET_SERVER_ENV.php",
    "/ntl/api/PES2022/gate_CMD_LOGIN.php",
    "/ntl/api/PES2022/CmdGetServerEnv.php",
    "/ntl/api/PES2022/CmdLogin.php",
    "/ntl/api/PES2022/ReportLog.php",       # control: this one is real
    "/ntl/api/GateInfo.php",                # control: real too
]


def body_for(msgid: str, kind: str) -> tuple[bytes, str]:
    """-> (bytes, content-type)"""
    if kind == "json":
        d = {"msgid": msgid, "rqid": 0, "user_id": UID, "session_id": "",
             "my_platform": "Android", "s_keyword": "", "lang": "US",
             "region": "US", "platform": "Android", "client_version": VER}
        return (b"req=" + urllib.parse.quote(json.dumps(
            d, separators=(",", ":"))).encode(),
            "application/x-www-form-urlencoded")
    if kind == "veronly":
        d = {"msgid": msgid, "rqid": 0, "user_id": "", "session_id": "",
             "my_platform": "", "s_keyword": "", "lang": "", "region": "",
             "platform": "", "client_version": VER}
        return msgpack.packb(d, use_bin_type=True), \
            "application/x-www-form-urlencoded"
    # kind == "msgpack": the game's own key order, real values
    d = {"msgid": msgid, "rqid": 0, "user_id": UID, "session_id": "",
         "my_platform": "Android", "s_keyword": "", "lang": "US",
         "region": "US", "platform": "Android", "client_version": VER}
    return msgpack.packb(d, use_bin_type=True), \
        "application/x-www-form-urlencoded"


def send(tls: bool, host: str, path: str, body: bytes, ct: str):
    ip = socket.gethostbyname(host)
    raw = socket.create_connection((ip, 443 if tls else 80), timeout=10)
    s = raw
    if tls:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        s = ctx.wrap_socket(raw, server_hostname=host)
    s.settimeout(12)
    req = ("POST %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n"
           "Content-Type: %s\r\nContent-Length: %d\r\n"
           "Connection: close\r\n\r\n" % (path, host, ct, len(body))).encode()
    s.sendall(req + body)
    d = b""
    while len(d) < 4000:
        b = s.recv(2000)
        if not b:
            break
        d += b
    s.close()
    line = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return line, d.partition(b"\r\n\r\n")[2][:100]


def main() -> int:
    print("### TLS host %s" % TLS_HOST, flush=True)
    for path in PATHS_TLS:
        for kind in ("msgpack", "veronly", "json"):
            msgid = ("CMD_GET_SERVER_ENV" if "ENV" in path or
                     "ServerEnv" in path else "CMD_LOGIN")
            body, ct = body_for(msgid, kind)
            try:
                line, b = send(True, TLS_HOST, path, body, ct)
            except Exception as e:
                line, b = "ERR %s: %s" % (type(e).__name__, str(e)[:60]), b""
            flag = "" if "500" in line else "   <<<<<< NEW"
            print("  %-46s %-8s %-30s %r %s"
                  % (path.split("/")[-1], kind, line, b, flag), flush=True)

    print("\n### HTTP host %s" % HTTP_HOST, flush=True)
    for path in PATHS_HTTP:
        msgid = ("CMD_GET_SERVER_ENV" if "ServerEnv" in path
                 else "CMD_LOGIN")
        body, ct = body_for(msgid, "json")
        try:
            line, b = send(False, HTTP_HOST, path, body, ct)
        except Exception as e:
            line, b = "ERR %s: %s" % (type(e).__name__, str(e)[:60]), b""
        flag = "" if ("404" in line or "500" in line) else "   <<<<<< NEW"
        print("  %-46s %-8s %-30s %r %s"
              % (path, "json", line, b, flag), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
