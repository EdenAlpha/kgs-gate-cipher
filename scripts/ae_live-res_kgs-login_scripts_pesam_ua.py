#!/usr/bin/env python3
"""The one header we never sent: User-Agent: PESAM.

The app has TWO HTTP layers.  The native curl sends PES/1.0 (...).  The Java
layer (jp.konami.android.common.HttpImpl / Cronet) sends:

    User-Agent: PESAM
    Content-Type: application/x-www-form-urlencoded
    cookie: <session>

We have never sent PESAM.  Try it against the gate.
"""
from __future__ import annotations

import socket
import ssl

HOST = "pes22-game.cs.konami.net"
FORM = "application/x-www-form-urlencoded"
BODY = open("real_body.bin", "rb").read()


def post(path, body, ct, ua, extra=()):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    L = [f"POST {path} HTTP/1.1", f"Host: {HOST}", f"User-Agent: {ua}",
         "Accept: */*", "Connection: close"]
    if ct:
        L.append("Content-Type: " + ct)
    for e in extra:
        L.append(e)
    L.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    s.settimeout(25)
    d = b""
    while len(d) < 65536:
        b = s.recv(8192)
        if not b:
            break
        d += b
    s.close()
    st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return st, d.partition(b"\r\n\r\n")[2]


def get(path, ua):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: {ua}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
    s.settimeout(25)
    d = b""
    while len(d) < 65536:
        b = s.recv(8192)
        if not b:
            break
        d += b
    s.close()
    st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return st, d.partition(b"\r\n\r\n")[2]


UAS = [
    "PESAM",
    "PESAM/6.0.1",
    "PES/1.0 ( ; 0; ; 6597086477512; ; ; ; )",
    "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)",
]

print("=== gate_CMD_LOGIN.php with each UA ===", flush=True)
for ua in UAS:
    for label, body, ct in (
            ("raw msgpack", BODY, FORM),
            ("req=<hex>", b"req=" + BODY.hex().encode(), FORM),
            ("json", b'{"msgid":"CMD_LOGIN","rqid":1}',
             "application/json")):
        try:
            st, bd = post("/pes22/gate/gate_CMD_LOGIN.php", body, ct, ua)
        except Exception as e:
            print(f"  UA={ua[:22]:22s} {label:14s} ERR {type(e).__name__}",
                  flush=True)
            continue
        blank = bd.strip() in (b"", b"0", b"0\r\n\r\n")
        tag = "" if (st.startswith("HTTP/1.1 500") and blank) \
            else "   <<<<<< DIFFERENT!"
        print(f"  UA={ua[:22]:22s} {label:14s} {st}  {bd[:140]!r}{tag}",
              flush=True)

print("\n=== with cookie + PESAM (Java layer shape) ===", flush=True)
for ck in ("session=", "session_id=1790385845048", "PHPSESSID=",
           "konami_session=1790385845048"):
    try:
        st, bd = post("/pes22/gate/gate_CMD_LOGIN.php", BODY, FORM, "PESAM",
                      ("Cookie: " + ck,))
    except Exception as e:
        print(f"  cookie={ck[:30]:30s} ERR {type(e).__name__}", flush=True)
        continue
    blank = bd.strip() in (b"", b"0", b"0\r\n\r\n")
    tag = "" if (st.startswith("HTTP/1.1 500") and blank) \
        else "   <<<<<< DIFFERENT!"
    print(f"  cookie={ck[:30]:30s} {st}  {bd[:140]!r}{tag}", flush=True)

print("\n=== GET with PESAM + query string (Java appends ?query for GET) ===",
      flush=True)
q = "msgid=CMD_LOGIN&req=" + BODY.hex()
for path in (f"/pes22/gate/gate_CMD_LOGIN.php?{q}",
             f"/pes22/gate/gate_CMD_GET_SERVER_ENV.php?{q}",
             "/pes22/gate/gate_CMD_LOGIN.php?msgid=CMD_LOGIN"):
    try:
        st, bd = get(path[:120], "PESAM")
    except Exception as e:
        print(f"  GET {path[:60]:60s} ERR {type(e).__name__}", flush=True)
        continue
    blank = bd.strip() in (b"", b"0", b"0\r\n\r\n")
    tag = "" if (st.startswith("HTTP/1.1 500") and blank) \
        else "   <<<<<< DIFFERENT!"
    print(f"  GET {path[:60]:60s} {st}  {bd[:140]!r}{tag}", flush=True)
