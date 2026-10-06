#!/usr/bin/env python3
"""POST the game's own body to the gate over real HTTP/2.

The endpoint prefers h2 (ALPN picks it whenever the client offers it) and the
real game certainly speaks h2; everything tried so far was HTTP/1.1.
"""
from __future__ import annotations

import socket
import ssl
import sys

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
BODY = open("getserverenv_body.bin", "rb").read()
UA = open("game_user_agent.txt").read().strip()


def h2_post(path, body: bytes, ct: str, ua: str, extra=(), host=HOST):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    sock = ctx.wrap_socket(socket.create_connection((host, 443), timeout=30),
                           server_hostname=host)
    if sock.selected_alpn_protocol() != "h2":
        sock.close()
        raise RuntimeError("server refused h2")

    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    headers = [
        (":method", "POST"), (":scheme", "https"), (":authority", host),
        (":path", path), ("accept", "*/*"), ("user-agent", ua),
        ("content-length", str(len(body))),
    ]
    if ct:
        headers.append(("content-type", ct))
    headers.extend(extra)
    conn.send_headers(1, headers, end_stream=False)
    conn.send_data(1, body, end_stream=True)
    sock.sendall(conn.data_to_send())

    status, headers_out, body_out = None, [], b""
    sock.settimeout(30)
    while True:
        data = sock.recv(65535)
        if not data:
            break
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                status = dict(ev.headers)
            elif isinstance(ev, h2.events.DataReceived):
                body_out += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                sock.sendall(conn.data_to_send())
                sock.close()
                return status, body_out
        out = conn.data_to_send()
        if out:
            sock.sendall(out)
    sock.close()
    return status, body_out


CASES = [
    ("form CT + raw msgpack", BODY, "application/x-www-form-urlencoded", ()),
    ("octet-stream + raw", BODY, "application/octet-stream", ()),
    ("form CT + req=<hex>", b"req=" + BODY.hex().encode(),
     "application/x-www-form-urlencoded", ()),
    ("soap CT + raw", BODY, 'text/xml; charset="utf-8"', ()),
    ("x-msgpack + raw", BODY, "application/x-msgpack", ()),
]

for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
    path = "/pes22/gate/gate_%s.php" % msgid
    print("==", path)
    for label, body, ct, extra in CASES:
        try:
            st, bd = h2_post(path, body, ct, UA, extra)
        except Exception as e:
            print("  %-24s ERR %s: %s" % (label, type(e).__name__, e))
            continue
        line = " ".join(f"{k}={v}" for k, v in list(st.items())
                        if k in (":status", "content-type", "server"))
        flag = "" if st.get(":status") != "500" else "   <<<<<< 500"
        print("  %-24s %s  %r%s" % (label, line, bd[:240], flag))
