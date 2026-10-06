#!/usr/bin/env python3
"""Aim the gRPC probe at ONE explicit IP (SNI/:authority stay the real host).

Usage:
    python probe_game_ip.py --ip 54.203.69.122 --body empty
    python probe_game_ip.py --ip 54.203.69.122 --body env
    python probe_game_ip.py --ip 54.203.69.122 --body login

--body env/login wraps the game's own MessagePack body in a CommandRequest
envelope (same builder as login_body_grpc.py). Prints :status + grpc-status
+ grpc-message + any response bytes.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import struct
import sys

import msgpack

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
HERE = __file__.rsplit("\\", 1)[0] if "\\" in __file__ else "."


def varint(v):
    o = bytearray()
    while True:
        x = v & 0x7F
        v >>= 7
        o.append(x | 0x80 if v else x)
        if not v:
            return bytes(o)


def fstr(f, s):
    raw = s if isinstance(s, (bytes, bytearray)) else s.encode()
    return bytes([f << 3 | 2]) + varint(len(raw)) + raw


def fvarint(f, v):
    return bytes([f << 3 | 0]) + varint(v)


def request(msgid, body, path, pack):
    return fstr(1, msgid) + fvarint(2, pack) + fstr(3, body) + fstr(4, path)


def frame(p):
    return b"\x00" + struct.pack(">I", len(p)) + p


def probe(ip, payload: bytes) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    ctx.set_ciphers(CIPHERS)
    s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=20),
                        server_hostname=HOST)
    print("tls=%s alpn=%s" % (s.version(), s.selected_alpn_protocol()),
          flush=True)
    c = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding="utf-8"))
    c.initiate_connection()
    c.send_headers(1, [(":method", "POST"), (":scheme", "https"),
                       (":authority", HOST), (":path", METHOD),
                       ("content-type", "application/grpc"),
                       ("te", "trailers"),
                       ("user-agent", "grpc-c/1.0 (android; arm64; pesam)"),
                       ("grpc-encoding", "identity"),
                       ("grpc-accept-encoding", "identity")],
                   end_stream=False)
    c.send_data(1, frame(payload), end_stream=True)
    s.sendall(c.data_to_send())
    s.settimeout(20)
    hdrs, trail, out = {}, {}, b""
    try:
        while True:
            d = s.recv(65535)
            if not d:
                break
            for ev in c.receive_data(d):
                if isinstance(ev, h2.events.ResponseReceived):
                    hdrs = dict(ev.headers)
                elif isinstance(ev, h2.events.DataReceived):
                    out += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    trail = dict(ev.headers)
            o = c.data_to_send()
            if o:
                s.sendall(o)
            if hdrs and (trail or out):
                break
            if hdrs and out == b"":
                # headers-only (trailers-only) response: done
                break
    except socket.timeout:
        pass
    s.close()
    print(":status =", hdrs.get(":status"), flush=True)
    print("grpc-status =",
          trail.get("grpc-status", hdrs.get("grpc-status", "-")), flush=True)
    print("grpc-message =",
          (trail.get("grpc-message", hdrs.get("grpc-message", "")) or "")[:200],
          flush=True)
    print("data %dB: %r" % (len(out), out[:200]), flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="54.203.69.122")
    ap.add_argument("--body", default="empty",
                    choices=("empty", "env", "realenv", "login"))
    a = ap.parse_args()
    if a.body == "empty":
        payload = b""
    elif a.body == "env":
        raw = open(HERE + "\\getserverenv_body.bin", "rb").read()
        payload = request("CMD_GET_SERVER_ENV", raw,
                          "gate/gate_CMD_GET_SERVER_ENV.php", 1)
    elif a.body == "realenv":
        d = {"msgid": "CMD_GET_SERVER_ENV", "rqid": 0,
             "user_id": "3c5aad3c6b8425c611ebe2f5da6c25af",
             "session_id": "", "my_platform": "Android", "s_keyword": "",
             "lang": "US", "region": "US", "platform": "Android",
             "client_version": "6.0.1"}
        raw = msgpack.packb(d, use_bin_type=True)
        payload = request("CMD_GET_SERVER_ENV", raw,
                          "gate/gate_CMD_GET_SERVER_ENV.php", 1)
    else:
        raw = open(HERE + "\\login_body.bin", "rb").read()
        payload = request("CMD_LOGIN", raw, "gate/gate_CMD_LOGIN.php", 1)
    print("probe %s body=%s (%dB envelope)" % (a.ip, a.body, len(payload)),
          flush=True)
    probe(a.ip, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
