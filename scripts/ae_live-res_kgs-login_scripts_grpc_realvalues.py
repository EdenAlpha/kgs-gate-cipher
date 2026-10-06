#!/usr/bin/env python3
"""gRPC with the REAL identity values (not placeholders).

real_body.bin (used by all gRPC probes so far) carries user_id=0 (int),
my_platform='', lang='en' -- never the working app's values.  This sends
exactly what the user's capture shows the working app sends.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import socket
import ssl

import h2.config
import h2.connection
import h2.events
import msgpack

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
UA = "grpc-c/1.0 (android; arm64; pesam)"
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")

UID = "3c5aad3c6b8425c611ebe2f5da6c25af"
VER = "6.0.1"


def enc_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)


def enc_str(field: int, s) -> bytes:
    raw = s.encode() if isinstance(s, str) else bytes(s)
    return bytes([field << 3 | 2]) + enc_varint(len(raw)) + raw


def run(msgid: str, user_id, extra: dict | None = None) -> None:
    d = {"msgid": msgid, "rqid": 0, "user_id": user_id, "session_id": "",
         "my_platform": "Android", "s_keyword": "", "lang": "US",
         "region": "US", "platform": "Android", "client_version": VER}
    if extra:
        d.update(extra)
    body = msgpack.packb(d, use_bin_type=True)
    path = "gate/gate_%s.php" % msgid
    req = (enc_str(1, msgid) + bytes([2 << 3 | 0]) + enc_varint(1)
           + enc_str(3, body) + enc_str(4, path))
    frame = b"\x00" + struct.pack(">I", len(req)) + req
    print("\n=== %s user_id=%r body=%dB ===" % (msgid, user_id, len(body)),
          flush=True)

    ip = socket.gethostbyname(HOST)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    ctx.set_ciphers(CIPHERS)
    s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=12),
                        server_hostname=HOST)
    print("  tls=%s alpn=%r" % (s.version(), s.selected_alpn_protocol()),
          flush=True)
    s.settimeout(15)
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding="utf-8"))
    conn.initiate_connection()
    conn.send_headers(1, [
        (":method", "POST"), (":scheme", "https"), (":authority", HOST),
        (":path", METHOD), ("content-type", "application/grpc"),
        ("te", "trailers"), ("user-agent", UA),
        ("grpc-encoding", "identity"), ("grpc-accept-encoding", "identity"),
    ], end_stream=False)
    conn.send_data(1, frame, end_stream=True)
    s.sendall(conn.data_to_send())
    try:
        for _ in range(40):
            data = s.recv(65535)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    print("  HDRS %s" % dict(ev.headers), flush=True)
                elif isinstance(ev, h2.events.DataReceived):
                    print("  DATA %dB %r" % (len(ev.data), ev.data[:200]),
                          flush=True)
                elif isinstance(ev, h2.events.TrailersReceived):
                    print("  TRAILERS %s" % dict(ev.headers), flush=True)
                elif isinstance(ev, h2.events.StreamEnded):
                    print("  ENDED", flush=True)
            s.sendall(conn.data_to_send())
    except socket.timeout:
        print("  (timeout)", flush=True)
    except Exception as e:
        print("  ERR %s: %s" % (type(e).__name__, str(e)[:70]), flush=True)
    finally:
        s.close()


def main() -> int:
    run("CMD_GET_SERVER_ENV", UID)
    run("CMD_GET_SERVER_ENV", 0)
    run("CMD_GET_KGS_GUEST_LOGIN_TOKEN", UID)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
