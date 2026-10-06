#!/usr/bin/env python3
"""Header-by-header ALB rule sweep on the real gRPC path.

415 without content-type, 464 for GET => the listener has rules matching on
headers.  If one rule (header X present) forwards to a healthy target group and
the fallback rule forwards to a dead one, adding X flips 502 -> real response.
Try each plausible header alone, then all combined.
"""
from __future__ import annotations

import socket
import ssl
import sys
import time

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")

BASE = [
    ("content-type", "application/grpc"),
    ("te", "trailers"),
    ("user-agent", "grpc-c/1.0 (android; arm64; pesam)"),
]

CANDIDATES = [
    ("grpc-accept-encoding", "gzip,deflate"),
    ("grpc-encoding", "identity"),
    ("grpc-timeout", "10S"),
    ("accept-encoding", "gzip"),
    ("accept", "*/*"),
    ("grpc-accept-encoding", "gzip"),
    ("user-agent", "grpc-c/1.17.1 (android; arm64; pesam)"),
    ("user-agent", "grpc-c/1.0 (Android 15; arm64; pesam)"),
    ("content-encoding", "identity"),
    ("x-grpc-web", "1"),
    ("x-kgs-title", "PES2022"),
    ("title-code", "PES2022"),
    ("client-version", "6.0.1"),
    ("x-client-version", "6.0.1"),
    ("x-title-code", "PES2022"),
    ("x-platform", "PES"),
    ("x-locale", "US"),
    ("origin", "https://pes22-game.cs.konami.net"),
    ("x-requested-with", "jp.konami.pesam"),
]


def probe(extra, payload=b"\x00\x00\x00\x00\x00") -> str:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.maximum_version = ssl.TLSVersion.TLSv1_2
    c.set_alpn_protocols(["grpc-exp", "h2"])
    c.set_ciphers(CIPHERS)
    ip = socket.gethostbyname(HOST)
    t0 = time.time()
    try:
        s = c.wrap_socket(socket.create_connection((ip, 443), timeout=6),
                          server_hostname=HOST)
    except Exception as e:
        return "connect-fail %s" % e
    s.settimeout(6)
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    headers = [(":method", "POST"), (":scheme", "https"),
               (":authority", HOST), (":path", METHOD)] + extra
    conn.send_headers(1, headers, end_stream=False)
    conn.send_data(1, payload, end_stream=True)
    s.sendall(conn.data_to_send())
    out = "no-response"
    end = time.time() + 6
    while time.time() < end:
        try:
            d = s.recv(65535)
        except socket.timeout:
            break
        if not d:
            break
        for ev in conn.receive_data(d):
            if isinstance(ev, h2.events.ResponseReceived):
                h = dict(ev.headers)
                out = "%.2fs %s g=%s %s" % (time.time() - t0, h.get(":status"),
                                            h.get("grpc-status", "-"),
                                            h.get("grpc-message", "-")[:40])
        s.sendall(conn.data_to_send())
    s.close()
    return out


def main() -> int:
    print("== baseline ==")
    print("   base            ", probe(BASE))
    print("\n== one candidate added at a time ==")
    for k, v in CANDIDATES:
        # replace if same key already present, else append
        extra = [(kk, vv) for kk, vv in BASE if kk != k] + [(k, v)]
        print("   %-26s %-22s %s" % (k, v[:22], probe(extra)))
    print("\n== all candidates together ==")
    merged = []
    for k, v in CANDIDATES:
        merged = [(kk, vv) for kk, vv in merged if kk != k] + [(k, v)]
    extra = [(kk, vv) for kk, vv in BASE if kk not in dict(CANDIDATES)] + merged
    print("   ", probe(extra))
    return 0


if __name__ == "__main__":
    sys.exit(main())
