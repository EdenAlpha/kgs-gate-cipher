#!/usr/bin/env python3
"""Talk to the IP the phone actually used (54.218.129.95) over gRPC h2,
plus the gate over HTTP/1.1 and HTTPS, with the app's exact TLS/ALPN profile."""
from __future__ import annotations

import socket
import ssl
import sys
import time

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
IP = "54.218.129.95"
METHOD = "/command_service.CommandService/CommandStream"
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")


def ctx(protos):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.maximum_version = ssl.TLSVersion.TLSv1_2
    c.set_alpn_protocols(protos)
    c.set_ciphers(CIPHERS)
    return c


def grpc_probe(ip: str, method: str, payload: bytes = b"\x00\x00\x00\x00\x00"):
    t0 = time.time()
    try:
        s = ctx(["grpc-exp", "h2"]).wrap_socket(
            socket.create_connection((ip, 443), timeout=8), server_hostname=HOST)
    except Exception as e:
        print("   connect fail %s: %s" % (ip, e))
        return
    s.settimeout(8)
    print("   TLS ok %.2fs proto=%s alpn=%s peer=%s" % (
        time.time() - t0, s.version(), s.selected_alpn_protocol(),
        s.getpeercert() is not None))
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    conn.send_headers(1, [
        (":method", "POST"), (":scheme", "https"), (":authority", HOST),
        (":path", method),
        ("content-type", "application/grpc"), ("te", "trailers"),
        ("user-agent", "grpc-c/1.0 (android; arm64; pesam)"),
    ], end_stream=False)
    conn.send_data(1, payload, end_stream=True)
    s.sendall(conn.data_to_send())
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            d = s.recv(65535)
        except socket.timeout:
            break
        if not d:
            print("   EOF")
            break
        for ev in conn.receive_data(d):
            if isinstance(ev, h2.events.ResponseReceived):
                print("   TTFB=%.2fs %s" % (time.time() - t0, dict(ev.headers)))
            elif isinstance(ev, h2.events.TrailersReceived):
                print("   TRAILERS %s" % dict(ev.headers))
            elif isinstance(ev, h2.events.DataReceived):
                print("   DATA %d bytes: %s" % (len(ev.flow_controlled_data),
                                                ev.data[:40].hex()))
                conn.acknowledge_received_data(ev.flow_controlled_data, 1)
        s.sendall(conn.data_to_send())
    s.close()


def http_probe(ip: str, path: str, tls: bool, host: str = HOST):
    t0 = time.time()
    req = ("POST %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n"
           "Content-Length: 7\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           "Connection: close\r\n\r\nreq=abc" % (path, host))
    try:
        raw = socket.create_connection((ip, 80 if not tls else 443), timeout=8)
        if tls:
            s = ctx(["http/1.1"]).wrap_socket(raw, server_hostname=host)
        else:
            s = raw
        s.settimeout(8)
        s.sendall(req.encode())
        buf = b""
        while True:
            try:
                d = s.recv(65535)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
            if b"\r\n\r\n" in buf and len(buf) > 400:
                break
        s.close()
        head = buf.split(b"\r\n\r\n")[0].decode(errors="replace")
        print("   [%s:%d %s] %.2fs  %s" % (ip, 443 if tls else 80, path,
                                           time.time() - t0,
                                           head.replace("\r\n", " | ")[:220]))
    except Exception as e:
        print("   [%s %s] ERR %s" % (ip, path, e))


def main() -> int:
    for ip in (IP,):
        print("== gRPC method on %s ==" % ip)
        grpc_probe(ip, METHOD)
        print("== gRPC fake method on %s ==" % ip)
        grpc_probe(ip, "/x.X/Y")
        print("== gate over HTTP/1.1 on %s ==" % ip)
        http_probe(ip, "/ntl/api/GateInfo.php", False, "ntl.service.konami.net")
        http_probe(ip, "/pes22/gate/gate_1.php", False)
        print("== gate over HTTPS on %s ==" % ip)
        http_probe(ip, "/pes22/gate/gate_1.php", True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
