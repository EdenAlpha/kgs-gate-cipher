#!/usr/bin/env python3
"""Timestamped gRPC health watch: probe every 60s, log status + latency.
Answers: is the backend flapping, down for everyone, or only down for us?"""
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
DURATION_S = int(sys.argv[1]) if len(sys.argv) > 1 else 1800
INTERVAL_S = int(sys.argv[2]) if len(sys.argv) > 2 else 60


def probe() -> str:
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
    conn.send_headers(1, [
        (":method", "POST"), (":scheme", "https"), (":authority", HOST),
        (":path", METHOD),
        ("content-type", "application/grpc"), ("te", "trailers"),
        ("user-agent", "grpc-c/1.0 (android; arm64; pesam)"),
    ], end_stream=False)
    conn.send_data(1, b"\x00\x00\x00\x00\x00", end_stream=True)
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
                                            h.get("grpc-message", "-"))
        s.sendall(conn.data_to_send())
    s.close()
    return out


def main() -> int:
    t_end = time.time() + DURATION_S
    n = 0
    while time.time() < t_end:
        n += 1
        print("%s  [%d] %s" % (time.strftime("%H:%M:%S"), n, probe()), flush=True)
        time.sleep(INTERVAL_S)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
