#!/usr/bin/env python3
"""Probe the LIVE Konami PHP directory.

From the capture (plaintext, so ground truth):

    ntl.service.konami.net
      POST /ntl/api/GateInfo.php          -> 200 + "STATUS: 200 ..."   (live!)
      POST /ntl/api/PES2022/ReportLog.php -> 200                        (live!)

So /ntl/api/ and /ntl/api/PES2022/ are working PHP directories with real
scripts -- unlike /pes22/gate/ on pes22-game, which fatals on everything.
Try the command names there.
"""
from __future__ import annotations

import socket

HOST = "ntl.service.konami.net"
FORM = "application/x-www-form-urlencoded"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
HEX = open("real_body.bin", "rb").read().hex()
PREFIX = ("1790386120_2_00000000000000000000000000000000_0000"
          "__e01a7766eb9df741b603aef191fb83d8_0")


def req(method, path, body=b"", ct=FORM):
    try:
        s = socket.create_connection((HOST, 80), timeout=20)
        L = [f"{method} {path} HTTP/1.1", f"Host: {HOST}",
             f"User-Agent: {UA}", "Accept: */*", "Connection: close"]
        if ct:
            L.append("Content-Type: " + ct)
        if body:
            L.append(f"Content-Length: {len(body)}")
        s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
        s.settimeout(20)
        d = b""
        while len(d) < 65536:
            b = s.recv(8192)
            if not b:
                break
            d += b
        s.close()
        st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
        return st, d.partition(b"\r\n\r\n")[2]
    except Exception as e:
        return f"ERR {type(e).__name__}", b""


NAMES = [
    "GateInfo", "ReportLog", "gate", "gate_CMD_LOGIN", "CMD_LOGIN",
    "CmdLogin", "CmdGetServerEnv", "gate_CMD_GET_SERVER_ENV",
    "CmdGetKgsGuestLoginToken", "gate_CMD_GET_KGS_GUEST_LOGIN_TOKEN",
    "CmdCreatejoinRoom", "gate_CMD_CREATEJOIN_ROOM", "Login", "login",
    "Auth", "auth", "Session", "session", "Api", "api", "Index", "index",
    "CmdGetGameId", "CmdCreateUser", "gate_CMD_CREATE_USER",
    "CmdGetSessionId", "CmdSetOnlineStats", "CmdGetTurnServerList",
    "gate_CMD_CONNECT_GRPC", "CmdConnectGrpc",
]
DIRS = ["/ntl/api/", "/ntl/api/PES2022/", "/ntl/api/pes22/", "/ntl/",
        "/ntl/PES2022/", "/api/", "/api/PES2022/", "/"]

BODY_FORM = b"type=pde&prefix=" + PREFIX.encode() + b"&ver=4&dat=" + HEX.encode()

print("=== live directory: ntl.service.konami.net (plain HTTP) ===\n",
      flush=True)

# control first: GateInfo and ReportLog must still answer 200
print("--- controls (must be 200) ---", flush=True)
st, bd = req("POST", "/ntl/api/GateInfo.php",
             b"req=" + b'{"titleCode":"pes22","locale":"US","version":"6.0.1",'
             b'"extra":"","apiLevel":4}'.hex().encode())
print(f"  POST /ntl/api/GateInfo.php          {st}  {bd[:80]!r}", flush=True)
st, bd = req("POST", "/ntl/api/PES2022/ReportLog.php", BODY_FORM)
print(f"  POST /ntl/api/PES2022/ReportLog.php {st}  {bd[:80]!r}\n",
      flush=True)

print("--- probing command names ---", flush=True)
hits = []
for d in DIRS:
    for n in NAMES:
        path = d + n + ".php"
        st, bd = req("POST", path, BODY_FORM)
        code = st.split(" ")[1] if st.startswith("HTTP") else "?"
        if code not in ("404",):
            mark = "   <<<< NOT 404"
            if code == "200":
                mark = "   <<<< 200 LIVE"
            print(f"  {path:52s} {st}  {bd[:90]!r}{mark}", flush=True)
            hits.append((path, st, bd))

print(f"\n=== {len(hits)} non-404 ===", flush=True)
for p, st, bd in hits:
    print(f"  {p:52s} {st}  {bd[:120]!r}", flush=True)
