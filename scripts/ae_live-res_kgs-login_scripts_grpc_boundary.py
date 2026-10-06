#!/usr/bin/env python3
"""Exactly what separates grpc-status:0 from grpc-status:14?

Observed: empty stream (headers only, half-close) -> 0 OK.
          ANY CommandRequest with data            -> 14 UNAVAILABLE.

So find the precise boundary.  Minimal valid proto3 messages, valid UTF-8
only (proto3 `string` fields reject non-UTF-8, and raw MessagePack is not
UTF-8 -- which may itself be the rejection cause).
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


def call(label, payload, end_stream=True, compress=False):
    """payload=None -> headers only (half-close)."""
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
    if payload is not None:
        fr = frame(payload)
        if compress:
            fr = b"\x01" + fr[1:]
        c.send_data(1, fr, end_stream=end_stream)
    elif end_stream:
        c.send_data(1, b"", end_stream=True)
    sock.sendall(c.data_to_send())

    sock.settimeout(10)
    status = grpc = msg = None
    out = b""
    trail = {}
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
                    out += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    trail = dict(ev.headers)
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
    g = trail.get("grpc-status", grpc)
    m = trail.get("grpc-message", msg)
    tag = "   <<<<" if (g not in ("14",) or status != "502") else ""
    print(f"  {label:44s} HTTP={status} grpc={g} msg={m} "
          f"body={len(out)}B{tag}", flush=True)
    return g


print("=== boundary hunt ===", flush=True)
call("A headers only, half-close", None, end_stream=True)
call("B headers only, stream left OPEN", None, end_stream=False)
call("C zero-length DATA frame", b"", end_stream=True)
call("D 1-byte payload (invalid proto)", b"\x00", end_stream=True)

# minimal valid CommandRequest: only field 1 (id) = ""  (valid UTF-8)
call("E CommandRequest{id:''}", fstr(1, ""), end_stream=True)
call("F CommandRequest{id:'CMD_LOGIN'}", fstr(1, "CMD_LOGIN"), end_stream=True)

# full but all-empty strings (valid UTF-8, no binary)
full = (fstr(1, "CMD_GET_SERVER_ENV") + fvarint(2, 1)
        + fstr(3, "") + fstr(4, "gate/gate_CMD_GET_SERVER_ENV.php"))
call("G full, req='' (empty string)", full, end_stream=True)

# req = hex of the body (valid UTF-8)
hexbody = open("real_body.bin", "rb").read().hex()
full2 = (fstr(1, "CMD_GET_SERVER_ENV") + fvarint(2, 1)
         + fstr(3, hexbody) + fstr(4, "gate/gate_CMD_GET_SERVER_ENV.php"))
call("H full, req=<hex>", full2, end_stream=True)

# req = raw body (NOT valid UTF-8 -> tests the UTF-8 theory)
rawbody = open("real_body.bin", "rb").read()
full3 = (fstr(1, "CMD_GET_SERVER_ENV") + fvarint(2, 1)
         + fstr(3, rawbody) + fstr(4, "gate/gate_CMD_GET_SERVER_ENV.php"))
call("I full, req=<raw non-UTF8>", full3, end_stream=True)

# packMode 0 (JSON) with a JSON string
full4 = (fstr(1, "CMD_GET_SERVER_ENV") + fvarint(2, 0)
         + fstr(3, '{"msgid":"CMD_GET_SERVER_ENV"}')
         + fstr(4, "gate/gate_CMD_GET_SERVER_ENV.php"))
call("J packMode=JSON, req=json", full4, end_stream=True)

# unknown field numbers (tests proto decode tolerance)
call("K field 99 string", fstr(99, "hello"), end_stream=True)
