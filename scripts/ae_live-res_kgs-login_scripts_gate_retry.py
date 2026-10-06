#!/usr/bin/env python3
"""Fire the proven login chain at the end of Konami's maintenance window.

Konami's daily maintenance runs 02:00-08:00 UTC.  Every probe inside that
window returns gate=500 / gRPC=502(awselb,grpc-status 14).  Outside it the
same endpoints work (proved by the user's capture at 19:30 UTC 2026-09-28).

This script waits for 08:05 UTC (or runs immediately with --now) and then
fires, using the REAL identity values recovered from the user's capture:
    client_version = 6.0.1   titleCode = PES2022   locale = US
    uid = 3c5aad3c6b8425c611ebe2f5da6c25af   libVer = 1.17.1-Android-15

First hit CMD_GET_SERVER_ENV (which the app runs first and which answers with
PUT_LOG_URL), then CMD_GET_KGS_GUEST_LOGIN_TOKEN (the KGS guest token we need
for the room), then CMD_LOGIN.
"""
from __future__ import annotations

import datetime as dt
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse

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

# UTC hour maintenance ends (inclusive margin)
MAINT_END_HOUR = 8


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


def body_env() -> bytes:
    d = {"msgid": "CMD_GET_SERVER_ENV", "rqid": 0, "user_id": UID,
         "session_id": "", "my_platform": "Android", "s_keyword": "",
         "lang": "US", "region": "US", "platform": "Android",
         "client_version": VER}
    return msgpack.packb(d, use_bin_type=True)


def body_guest() -> bytes:
    d = {"msgid": "CMD_GET_KGS_GUEST_LOGIN_TOKEN", "rqid": 0, "user_id": UID,
         "session_id": "", "my_platform": "Android", "s_keyword": "",
         "lang": "US", "region": "US", "platform": "Android",
         "client_version": VER}
    return msgpack.packb(d, use_bin_type=True)


def grpc_call(msgid: str, body: bytes, ip: str | None = None,
              hold: float = 15.0) -> str:
    path = "gate/gate_%s.php" % msgid
    frame = grpc_frame(command_request(msgid, body, path))
    ip = ip or socket.gethostbyname(HOST)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    ctx.set_ciphers(CIPHERS)
    raw = socket.create_connection((ip, 443), timeout=15)
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    s.settimeout(hold)

    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding="utf-8"))
    conn.initiate_connection()
    conn.send_headers(1, [
        (":method", "POST"), (":scheme", "https"),
        (":authority", HOST), (":path", METHOD),
        ("content-type", "application/grpc"), ("te", "trailers"),
        ("user-agent", UA), ("grpc-encoding", "identity"),
        ("grpc-accept-encoding", "identity"),
    ], end_stream=False)
    conn.send_data(1, frame, end_stream=True)
    s.sendall(conn.data_to_send())

    out, hdrs = [], {}
    try:
        while True:
            data = s.recv(65535)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    hdrs = dict(ev.headers)
                elif isinstance(ev, h2.events.DataReceived):
                    out.append(ev.data)
                elif isinstance(ev, h2.events.StreamEnded):
                    s.sendall(conn.data_to_send())
                    s.close()
                    return "hdrs=%s body=%r" % (hdrs, b"".join(out)[:400])
            s.sendall(conn.data_to_send())
    except socket.timeout:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return "hdrs=%s body=%r" % (hdrs, b"".join(out)[:400])


def gate_http(msgid: str) -> str:
    """The plain HTTPS gate endpoint (what the earlier probes used)."""
    body = msgpack.packb(
        {"msgid": msgid, "rqid": 0, "user_id": UID, "session_id": "",
         "my_platform": "Android", "s_keyword": "", "lang": "US",
         "region": "US", "platform": "Android", "client_version": VER},
        use_bin_type=True)
    ip = socket.gethostbyname(HOST)
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=15),
                         server_hostname=HOST) as s:
        s.settimeout(15)
        req = ("POST /pes22/gate/gate_%s.php HTTP/1.1\r\nHost: %s\r\n"
               "Accept: */*\r\nContent-Type: application/"
               "x-www-form-urlencoded\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n" % (msgid, HOST, len(body))).encode()
        s.sendall(req + body)
        d = b""
        while len(d) < 4000:
            b = s.recv(2000)
            if not b:
                break
            d += b
    return d.decode("latin1", "replace")[:400]


def main() -> int:
    now = dt.datetime.now(dt.timezone.utc)
    if "--now" not in sys.argv and now.hour < MAINT_END_HOUR:
        target = now.replace(hour=MAINT_END_HOUR, minute=5, second=0,
                             microsecond=0)
        wait = (target - now).total_seconds()
        print("[wait] maintenance window until %s UTC -- firing at %s "
              "(%.1f min from now)" % ("08:00", "08:05", wait / 60.0),
              flush=True)
        time.sleep(max(0, wait))
    print("[fire] %s UTC" % dt.datetime.now(dt.timezone.utc)
          .strftime("%Y-%m-%d %H:%M:%S"), flush=True)

    probes = (("gate CMD_GET_SERVER_ENV",
               lambda: gate_http("CMD_GET_SERVER_ENV")),
              ("gate CMD_GET_KGS_GUEST_LOGIN_TOKEN",
               lambda: gate_http("CMD_GET_KGS_GUEST_LOGIN_TOKEN")),
              ("grpc CMD_GET_SERVER_ENV",
               lambda: grpc_call("CMD_GET_SERVER_ENV", body_env())),
              ("grpc CMD_GET_KGS_GUEST_LOGIN_TOKEN",
               lambda: grpc_call("CMD_GET_KGS_GUEST_LOGIN_TOKEN",
                                 body_guest())))

    # keep firing every 20 min until the backend answers with something that
    # is not a maintenance signature (gate 500 / grpc 502-unavailable)
    for attempt in range(1, 40):
        print("\n##### attempt %d at %s UTC #####"
              % (attempt, dt.datetime.now(dt.timezone.utc)
                 .strftime("%H:%M:%S")), flush=True)
        alive = False
        for label, fn in probes:
            print("\n=== %s ===" % label, flush=True)
            try:
                r = fn()
                print("  " + r.replace("\n", "\n  "), flush=True)
                if ("502" not in r and "grpc-status': '14'" not in r
                        and "500 Internal" not in r):
                    alive = True
            except Exception as e:
                print("  ERR %s: %s" % (type(e).__name__, str(e)[:90]),
                      flush=True)
            time.sleep(1.0)
        if alive:
            print("\n[done] backend answered with real data -- run the KGS "
                  "login steps now.", flush=True)
            return 0
        time.sleep(20 * 60)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
