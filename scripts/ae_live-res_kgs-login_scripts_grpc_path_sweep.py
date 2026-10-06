#!/usr/bin/env python3
"""The 13-vs-14 split says `path` is a routing key.

  unparseable bytes -> 13 INTERNAL "Error deserializing request"  (parser)
  parseable msg     -> 14 UNAVAILABLE at 0ms in HEADERS           (router)
  no message        -> 0 OK                                       (stream open)

So a message with an unknown `path` gets "unavailable".  Sweep `path` forms.
Anything that is NOT 14 is the routing key we have been missing.
"""
from __future__ import annotations

import socket
import ssl
import struct

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
UA = "grpc-c/1.0 (android; arm64; pesam)"
BODY = open("real_body.bin", "rb").read()


def varint(v):
    o = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        o.append(b | 0x80 if v else b)
        if not v:
            return bytes(o)


def fstr(f, s):
    raw = s.encode("utf-8") if isinstance(s, str) else bytes(s)
    return bytes([f << 3 | 2]) + varint(len(raw)) + raw


def fvarint(f, v):
    return bytes([f << 3 | 0]) + varint(v)


def frame(p):
    return b"\x00" + struct.pack(">I", len(p)) + p


def call(payload):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    sock = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=20),
                           server_hostname=HOST)
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    c = h2.connection.H2Connection(config=cfg)
    c.initiate_connection()
    sock.sendall(c.data_to_send())
    c.send_headers(1, [(":method", "POST"), (":scheme", "https"),
                       (":authority", HOST), (":path", METHOD),
                       ("content-type", "application/grpc"),
                       ("te", "trailers"), ("user-agent", UA)],
                   end_stream=False)
    c.send_data(1, frame(payload), end_stream=True)
    sock.sendall(c.data_to_send())

    sock.settimeout(10)
    hdrs, trail, out = {}, {}, b""
    try:
        while True:
            d = sock.recv(65535)
            if not d:
                break
            for ev in c.receive_data(d):
                if isinstance(ev, h2.events.ResponseReceived):
                    hdrs = {k: v for k, v in ev.headers}
                elif isinstance(ev, h2.events.DataReceived):
                    out += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    trail = {k: v for k, v in ev.headers}
                elif isinstance(ev, h2.events.StreamEnded):
                    pass
            o = c.data_to_send()
            if o:
                sock.sendall(o)
            if hdrs:
                break
    except Exception:
        pass
    sock.close()
    g = trail.get("grpc-status") or hdrs.get("grpc-status")
    m = trail.get("grpc-message") or hdrs.get("grpc-message")
    return hdrs.get(":status"), g, m, out


def show(label, payload):
    st, g, m, out = call(payload)
    tag = "   <<<<<< NOT 14" if g != "14" else ""
    print(f"  {label:52s} HTTP={st} grpc={g} msg={m} {len(out)}B{tag}",
          flush=True)
    return g


MSG = "CMD_GET_SERVER_ENV"

PATHS = [
    "gate/gate_CMD_GET_SERVER_ENV.php",
    "gate/gate_CMD_GET_SERVER_ENV",
    "gate_CMD_GET_SERVER_ENV.php",
    "gate_CMD_GET_SERVER_ENV",
    "CMD_GET_SERVER_ENV.php",
    "CMD_GET_SERVER_ENV",
    "CmdGetServerEnv.php",
    "CmdGetServerEnv",
    "GetServerEnv.php",
    "GetServerEnv",
    "ServerEnv.php",
    "ServerEnv",
    "getserverenv",
    "/pes22/gate/gate_CMD_GET_SERVER_ENV.php",
    "/gate/gate_CMD_GET_SERVER_ENV.php",
    "/CMD_GET_SERVER_ENV.php",
    "pes22/gate/gate_CMD_GET_SERVER_ENV.php",
    "gate/gate_.php",
    "gate/gate.php",
    "gate.php",
    "CommandStream",
    "command_service.CommandService/CommandStream",
    "/command_service.CommandService/CommandStream",
    "CMD_GET_SERVER_ENV.php?msgid=CMD_GET_SERVER_ENV",
]

print("=== path sweep (id=CMD_GET_SERVER_ENV, req=<body>) ===", flush=True)
for p in PATHS:
    show(f"path={p[:48]}", fstr(1, MSG) + fvarint(2, 1) + fstr(3, BODY) + fstr(4, p))

print("\n=== id sweep (path=gate/gate_CMD_GET_SERVER_ENV.php) ===", flush=True)
P = "gate/gate_CMD_GET_SERVER_ENV.php"
for i in ("CMD_GET_SERVER_ENV", "CmdGetServerEnv", "GetServerEnv",
          "CMD_CONNECT_GRPC", "CMD_GET_GAME_ID", "CMD_HEARTBEAT_GRPC",
          "CMD_GET_KGS_GUEST_LOGIN_TOKEN", "CMD_SEND_AUTHORIZATION_CODE"):
    show(f"id={i}", fstr(1, i) + fvarint(2, 1) + fstr(3, BODY) + fstr(4, P))

print("\n=== field presence (no id / no path / no packMode / no req) ===",
      flush=True)
show("all four fields", fstr(1, MSG) + fvarint(2, 1) + fstr(3, BODY) + fstr(4, P))
show("path only", fstr(4, P))
show("id only", fstr(1, MSG))
show("id+path", fstr(1, MSG) + fstr(4, P))
show("path+req", fstr(3, BODY) + fstr(4, P))
show("id+path+packMode", fstr(1, MSG) + fvarint(2, 1) + fstr(4, P))
show("path only, no id, packMode=0", fvarint(2, 0) + fstr(4, P))

print("\n=== script-filename paths for other commands ===", flush=True)
for mid, script in (("CMD_GET_KGS_GUEST_LOGIN_TOKEN",
                     "CmdGetKgsGuestLoginToken.php"),
                    ("CMD_LOGIN", "CmdLogin.php"),
                    ("CMD_CREATEJOIN_ROOM", "CmdCreatejoinRoom.php"),
                    ("CMD_CONNECT_GRPC", "CmdConnectGrpc.php"),
                    ("CMD_HEARTBEAT_GRPC", "CmdHeartbeatGrpc.php")):
    for p in (script, f"gate/gate_{mid}.php", script[:-4]):
        show(f"{mid[:22]:22s} path={p}", fstr(1, mid) + fvarint(2, 1)
             + fstr(3, BODY) + fstr(4, p))
