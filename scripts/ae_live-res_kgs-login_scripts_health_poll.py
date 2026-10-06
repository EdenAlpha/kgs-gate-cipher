#!/usr/bin/env python3
"""Dumb health poll: gRPC status + gate HTTPS status every 10 min, forever.
No maintenance-window logic (that theory is dead). Logs everything."""
from __future__ import annotations

import socket
import ssl
import sys
import time
import urllib.request

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
INTERVAL = int(sys.argv[1]) if len(sys.argv) > 1 else 600


def grpc_once() -> str:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.maximum_version = ssl.TLSVersion.TLSv1_2
    c.set_alpn_protocols(["grpc-exp", "h2"])
    c.set_ciphers(CIPHERS)
    t0 = time.time()
    try:
        s = c.wrap_socket(socket.create_connection((HOST, 443), timeout=8),
                          server_hostname=HOST)
    except Exception as e:
        return "connect-fail %s" % e
    s.settimeout(8)
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
    end = time.time() + 8
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
                out = "%.2fs %s g=%s" % (time.time() - t0, h.get(":status"),
                                         h.get("grpc-status", "-"))
        s.sendall(conn.data_to_send())
    s.close()
    return out


def gate_once() -> str:
    try:
        r = urllib.request.urlopen(
            "https://%s/pes22/gate/gate_1.php" % HOST, data=b"req=abc",
            timeout=10)
        return "gate %s" % r.status
    except Exception as e:
        s = str(e)
        import re
        m = re.search(r"(HTTP Error \d+|500|404|464|502)", s)
        return "gate %s" % (m.group(1) if m else s[:60])


def main() -> int:
    n = 0
    while True:
        n += 1
        print("%s [%d] grpc=%s %s" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), n, grpc_once(), gate_once()),
            flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
