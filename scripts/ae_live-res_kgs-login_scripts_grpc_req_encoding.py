#!/usr/bin/env python3
"""The `req` field is TYPE_STRING.  The PHP form used req=<hex>.

So `req` is probably the HEX of the MessagePack body, not raw bytes.
That single difference would explain why the backend rejects our message.
"""
from __future__ import annotations

import base64
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
    raw = s.encode() if isinstance(s, str) else bytes(s)
    return bytes([f << 3 | 2]) + varint(len(raw)) + raw


def request(msgid, body, path, pack=1):
    return (fstr(1, msgid) + bytes([2 << 3 | 0]) + varint(pack)
            + fstr(3, body) + fstr(4, path))


def frame(p):
    return b"\x00" + struct.pack(">I", len(p)) + p


def call(label, msgid, body, path, extra=None):
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
    hdrs = [(":method", "POST"), (":scheme", "https"), (":authority", HOST),
            (":path", METHOD), ("content-type", "application/grpc"),
            ("te", "trailers"), ("user-agent", UA)]
    if extra:
        hdrs.extend(extra)
    c.send_headers(1, hdrs, end_stream=False)
    c.send_data(1, frame(request(msgid, body, path)), end_stream=True)
    sock.sendall(c.data_to_send())

    sock.settimeout(12)
    status = grpc = msg = None
    out_b = b""
    trailers = {}
    try:
        while True:
            d = sock.recv(65535)
            if not d:
                break
            for ev in c.receive_data(d):
                if isinstance(ev, h2.events.ResponseReceived):
                    h = dict(ev.headers)
                    status = h.get(":status")
                    grpc = h.get("grpc-status")
                    msg = h.get("grpc-message")
                elif isinstance(ev, h2.events.DataReceived):
                    out_b += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    trailers = dict(ev.headers)
                elif isinstance(ev, h2.events.StreamEnded):
                    break
            o = c.data_to_send()
            if o:
                sock.sendall(o)
            if status:
                break
    except socket.timeout:
        status = "(timeout)"
    except Exception as e:
        status = f"ERR {type(e).__name__}"
    sock.close()
    g = trailers.get("grpc-status", grpc)
    m = trailers.get("grpc-message", msg)
    tag = "   <<<<<< CHANGED" if (status != "502" or g != "14") else ""
    print(f"  {label:40s} HTTP={status} grpc={g} msg={m} "
          f"body={len(out_b)}B{tag}", flush=True)
    if out_b:
        print(f"      {out_b[:240]!r}", flush=True)
    if trailers:
        print(f"      trailers={trailers}", flush=True)
    return status, g, out_b


MSG = "CMD_GET_SERVER_ENV"
P = "gate/gate_CMD_GET_SERVER_ENV.php"

print("=== `req` field encodings ===", flush=True)
call("req=raw msgpack", MSG, BODY, P)
call("req=HEX(msgpack)", MSG, BODY.hex().encode(), P)
call("req=HEX upper", MSG, BODY.hex().upper().encode(), P)
call("req=BASE64", MSG, base64.b64encode(BODY), P)
call("req=empty", MSG, b"", P)
call("req=req=<hex>", MSG, b"req=" + BODY.hex().encode(), P)

print("\n=== id + path combos with HEX body ===", flush=True)
H = BODY.hex().encode()
for mid, p in (("CMD_GET_SERVER_ENV", "gate/gate_CMD_GET_SERVER_ENV.php"),
               ("CmdGetServerEnv", "CmdGetServerEnv.php"),
               ("CMD_GET_SERVER_ENV", "CmdGetServerEnv.php"),
               ("CMD_GET_SERVER_ENV", ""),
               ("CMD_CONNECT_GRPC", "gate/gate_CMD_CONNECT_GRPC.php")):
    call(f"id={mid[:20]} path={p[:18]}", mid, H, p)

print("\n=== with auth-ish metadata + HEX body ===", flush=True)
for meta in ([("authorization", "guest")],
             [("grpc-timeout", "30S")],
             [("x-konami-session", "1790385845048")],
             [("content-type", "application/grpc+proto")]):
    call(meta[0][0] + "=" + meta[0][1][:16], MSG, H, P, meta)

print("\n=== two-step: connect then command (2 streams) ===", flush=True)
# stream 1: CMD_CONNECT_GRPC, then stream 2: the real command
for mid, p, body in (("CMD_CONNECT_GRPC", "gate/gate_CMD_CONNECT_GRPC.php", H),
                     ("CMD_GET_SERVER_ENV", P, H)):
    call(f"stream: {mid}", mid, body, p)
