#!/usr/bin/env python3
"""Focused test: what makes CommandStream actually process a command?

Established:
  * the method is real (grpc-status 0 OK on empty stream, 12 UNIMPLEMENTED
    on wrong method names)
  * sending a CommandRequest gives 502 + grpc-status 14 UNAVAILABLE
  * the game's config says "use_http_command": false  -> gRPC is THE path

So we are reaching the handler but it rejects the message.  Vary the one
thing that is still guesswork: the `path` field's shape.
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
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)


def fstr(f, s):
    raw = s.encode() if isinstance(s, str) else bytes(s)
    return bytes([f << 3 | 2]) + varint(len(raw)) + raw


def request(msgid, body, path, pack=1):
    return (fstr(1, msgid) + bytes([2 << 3 | 0]) + varint(pack)
            + fstr(3, body) + fstr(4, path))


def frame(p):
    return b"\x00" + struct.pack(">I", len(p)) + p


def run(label, msgid, body, path, extra=None, keep_open=False):
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
            ("te", "trailers"), ("user-agent", UA),
            ("grpc-encoding", "identity"),
            ("grpc-accept-encoding", "identity")]
    if extra:
        hdrs.extend(extra)
    c.send_headers(1, hdrs, end_stream=False)
    payload = request(msgid, body, path)
    c.send_data(1, frame(payload), end_stream=not keep_open)
    sock.sendall(c.data_to_send())

    sock.settimeout(8)
    status = grpc = msg = None
    body_out = b""
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
                    body_out += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    trailers = dict(ev.headers)
                elif isinstance(ev, h2.events.StreamEnded):
                    break
            out = c.data_to_send()
            if out:
                sock.sendall(out)
            if status:
                break
    except socket.timeout:
        status = "(timeout)"
    except Exception as e:
        status = f"ERR {type(e).__name__}"
    sock.close()
    g2 = trailers.get("grpc-status", grpc)
    m2 = trailers.get("grpc-message", msg)
    tag = ""
    if g2 not in ("14", "unavailable", None):
        tag = "   <<<<<< NEW STATUS"
    if status not in ("502", "(timeout)") and status is not None:
        tag = "   <<<<<< NOT 502"
    print(f"  {label:44s} HTTP={status} grpc={g2} msg={m2} "
          f"body={len(body_out)}B{tag}", flush=True)
    if body_out:
        print(f"      {body_out[:180]!r}", flush=True)
    return g2, body_out


def main():
    print("=== path field shapes ===", flush=True)
    MSG = "CMD_GET_SERVER_ENV"
    shapes = [
        ("gate/gate_CMD_GET_SERVER_ENV.php", "gate/gate_%s.php"),
        ("CMD_GET_SERVER_ENV.php", "%s.php"),
        ("gate_CMD_GET_SERVER_ENV.php", "gate_%s.php"),
        ("CmdGetServerEnv.php", "CmdGetServerEnv.php"),
        ("CmdGetServerEnv", "CmdGetServerEnv"),
        ("CMD_GET_SERVER_ENV", "CMD_GET_SERVER_ENV"),
        ("/pes22/gate/gate_CMD_GET_SERVER_ENV.php", "full path"),
        ("https://pes22-game.cs.konami.net/pes22/gate/gate_CMD_GET_SERVER_ENV.php", "full url"),
        ("", "empty path"),
    ]
    for p, lbl in shapes:
        run(f"path={p[:38]}", MSG, BODY, p)

    print("\n=== payload variants (path=gate/gate_*.php) ===", flush=True)
    P = "gate/gate_CMD_GET_SERVER_ENV.php"
    run("req=real_body", MSG, BODY, P)
    run("req=empty", MSG, b"", P)
    run("req=json", MSG, b'{"msgid":"CMD_GET_SERVER_ENV"}', P)
    run("packMode=0 (json)", MSG, BODY, P, )

    print("\n=== msgid variants ===", flush=True)
    for m in ("CMD_GET_SERVER_ENV", "CMD_CONNECT_GRPC", "CMD_HEARTBEAT_GRPC",
              "CMD_GET_GAME_ID", "CMD_GET_KGS_GUEST_LOGIN_TOKEN"):
        run(f"msgid={m}", m, BODY, f"gate/gate_{m}.php")

    print("\n=== keep stream open, send 3 msgs ===", flush=True)
    # one stream, three requests
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
                       ("content-type", "application/grpc"), ("te", "trailers"),
                       ("user-agent", UA)], end_stream=False)
    for m in ("CMD_CONNECT_GRPC", "CMD_GET_SERVER_ENV", "CMD_LOGIN"):
        c.send_data(1, frame(request(m, BODY, f"gate/gate_{m}.php")),
                    end_stream=False)
    sock.sendall(c.data_to_send())
    sock.settimeout(10)
    got = []
    try:
        while True:
            d = sock.recv(65535)
            if not d:
                break
            for ev in c.receive_data(d):
                if isinstance(ev, h2.events.ResponseReceived):
                    h = dict(ev.headers)
                    print(f"  headers: status={h.get(':status')} "
                          f"grpc={h.get('grpc-status')} "
                          f"msg={h.get('grpc-message')}", flush=True)
                elif isinstance(ev, h2.events.DataReceived):
                    got.append(ev.data)
                    print(f"  <<< DATA {len(ev.data)}B {ev.data[:160]!r}",
                          flush=True)
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    print(f"  trailers: {dict(ev.headers)}", flush=True)
            out = c.data_to_send()
            if out:
                sock.sendall(out)
    except socket.timeout:
        print("  (10s timeout, stream still open)", flush=True)
    except Exception as e:
        print(f"  ERR {type(e).__name__}: {e}", flush=True)
    sock.close()


if __name__ == "__main__":
    main()
