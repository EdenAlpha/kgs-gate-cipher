#!/usr/bin/env python3
"""gRPC against the pool IPs never tested for gRPC (rotation may have hidden
a healthy node).  Fixed path, real values, TTFB printed."""
from __future__ import annotations

import socket
import ssl
import struct
import time

import h2.config
import h2.connection
import h2.events
import msgpack

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
UA = "grpc-c/1.0 (android; arm64; pesam)"
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
UID = "3c5aad3c6b8425c611ebe2f5da6c25af"
VER = "6.0.1"

IPS = ["32.189.12.38", "44.224.10.74", "52.40.209.32", "16.146.220.162",
       "35.162.196.95", "35.81.17.106", "44.229.198.107", "32.185.79.241",
       "34.218.97.216", "44.232.213.50"]


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


def run(ip: str) -> None:
    body = msgpack.packb(
        {"msgid": "CMD_GET_SERVER_ENV", "rqid": 0, "user_id": UID,
         "session_id": "", "my_platform": "Android", "s_keyword": "",
         "lang": "US", "region": "US", "platform": "Android",
         "client_version": VER}, use_bin_type=True)
    req = (enc_str(1, "CMD_GET_SERVER_ENV") + bytes([2 << 3 | 0])
           + enc_varint(1) + enc_str(3, body)
           + enc_str(4, "gate/gate_CMD_GET_SERVER_ENV.php"))
    frame = b"\x00" + struct.pack(">I", len(req)) + req

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    ctx.set_ciphers(CIPHERS)
    t0 = time.time()
    s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=10),
                        server_hostname=HOST)
    s.settimeout(10)
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
        for _ in range(25):
            data = s.recv(65535)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    print("  ip=%-16s TTFB=%.2fs %s"
                          % (ip, time.time() - t0, dict(ev.headers)),
                          flush=True)
                    s.close()
                    return
            s.sendall(conn.data_to_send())
    except Exception as e:
        print("  ip=%-16s ERR %s" % (ip, type(e).__name__), flush=True)
    finally:
        s.close()


def main() -> int:
    for ip in IPS:
        try:
            run(ip)
        except Exception as e:
            print("  ip=%-16s ERR %s: %s" % (ip, type(e).__name__,
                                             str(e)[:60]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
