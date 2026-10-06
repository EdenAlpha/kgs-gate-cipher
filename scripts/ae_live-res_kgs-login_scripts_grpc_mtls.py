#!/usr/bin/env python3
"""THE mTLS test: the app ships a client TLS certificate.

TLS 1.2 only + exactly 5 ciphers is the fingerprint of a client that pins a
restricted SSL context.  If the gate and/or the gRPC front end REQUIRE that
client certificate, then:
  * our certificate-less probes -> gate PHP fatal 500 (script reads the TLS
    client identity and dies without it) and gRPC 502/unavailable
  * the real app, which presents the cert -> works

The cert/key pair was extracted from the game's own binary (certs may be
shared; the keys are used here only for local TLS and are NOT committed).

Runs every probe both WITHOUT and WITH the client certificate so the
difference is unambiguous.
"""
from __future__ import annotations

import os
import socket
import ssl
import struct

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

CERT = os.path.join(HERE, "client_cert.pem")
KEY = os.path.join(HERE, "client_key.pem")
CHAIN = os.path.join(HERE, "chain.pem")

VER = "6.0.1"
UID = "3c5aad3c6b8425c611ebe2f5da6c25af"


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


def command_request(msgid, body, path, pack_mode=1) -> bytes:
    return (enc_str(1, msgid) + bytes([2 << 3 | 0]) + enc_varint(pack_mode)
            + enc_str(3, body) + enc_str(4, path))


def grpc_frame(p: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(p)) + p


def ctx_for(mtls: bool, alpn=("grpc-exp", "h2"), tls12=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if tls12:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(list(alpn))
    ctx.set_ciphers(CIPHERS)
    if mtls:
        # full chain if available, else leaf cert + key
        try:
            ctx.load_cert_chain(CERT, KEY)
        except ssl.SSLError:
            return None
    return ctx


def gate_http(mtls: bool) -> str:
    body = msgpack.packb(
        {"msgid": "CMD_GET_SERVER_ENV", "rqid": 0, "user_id": UID,
         "session_id": "", "my_platform": "Android", "s_keyword": "",
         "lang": "US", "region": "US", "platform": "Android",
         "client_version": VER}, use_bin_type=True)
    ip = socket.gethostbyname(HOST)
    ctx = ctx_for(mtls, alpn=("http/1.1",), tls12=False)
    if ctx is None:
        return "ERR cert/key load failed"
    with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=12),
                         server_hostname=HOST) as s:
        s.settimeout(15)
        req = ("POST /pes22/gate/gate_CMD_GET_SERVER_ENV.php HTTP/1.1\r\n"
               "Host: %s\r\nAccept: */*\r\nContent-Type: application/"
               "x-www-form-urlencoded\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n" % (HOST, len(body))).encode()
        s.sendall(req + body)
        d = b""
        while len(d) < 4000:
            b = s.recv(2000)
            if not b:
                break
            d += b
    return d.decode("latin1", "replace")[:300]


def grpc_call(mtls: bool, msgid="CMD_GET_KGS_GUEST_LOGIN_TOKEN") -> str:
    body = msgpack.packb(
        {"msgid": msgid, "rqid": 0, "user_id": UID, "session_id": "",
         "my_platform": "Android", "s_keyword": "", "lang": "US",
         "region": "US", "platform": "Android", "client_version": VER},
        use_bin_type=True)
    frame = grpc_frame(command_request(msgid, body,
                                       "gate/gate_%s.php" % msgid))
    ip = socket.gethostbyname(HOST)
    ctx = ctx_for(mtls)
    if ctx is None:
        return "ERR cert/key load failed"
    s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=12),
                        server_hostname=HOST)
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

    out, hdrs = [], {}
    try:
        while True:
            chunk = s.recv(65535)
            if not chunk:
                break
            for ev in conn.receive_data(chunk):
                if isinstance(ev, h2.events.ResponseReceived):
                    hdrs = dict(ev.headers)
                elif isinstance(ev, h2.events.DataReceived):
                    out.append(ev.data)
                elif isinstance(ev, h2.events.StreamEnded):
                    s.close()
                    return "hdrs=%s body=%r" % (hdrs, b"".join(out)[:300])
            s.sendall(conn.data_to_send())
    except Exception as e:
        return "ERR %s: %s | hdrs=%s body=%r" % (
            type(e).__name__, str(e)[:60], hdrs, b"".join(out)[:300])
    finally:
        try:
            s.close()
        except Exception:
            pass
    return "hdrs=%s body=%r" % (hdrs, b"".join(out)[:300])


def main() -> int:
    for label, fn in (("gate  no cert", lambda: gate_http(False)),
                      ("gate  WITH CLIENT CERT", lambda: gate_http(True)),
                      ("grpc  no cert", lambda: grpc_call(False)),
                      ("grpc  WITH CLIENT CERT", lambda: grpc_call(True))):
        print("\n=== %s ===" % label, flush=True)
        try:
            print("  " + fn().replace("\n", "\n  "), flush=True)
        except Exception as e:
            print("  ERR %s: %s" % (type(e).__name__, str(e)[:90]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
