#!/usr/bin/env python3
"""Single gRPC probe, optionally riding a tunnel so Konami sees another IP.

Direct (same as always):
    python tunnel_probe.py
Via a CONNECT proxy (e.g. phone tunnel exposing the phone's HTTP proxy):
    python tunnel_probe.py --proxy-host xxx.localhost.run --proxy-port 443 --tls-proxy
    python tunnel_probe.py --proxy-host 127.0.0.1 --proxy-port 8888

Identical bytes either way -- only the source IP Konami sees differs.
One probe ~= 10-15 KB on the wire.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
PORT = 443
METHOD = "/command_service.CommandService/CommandStream"
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")


def raw_connect(proxy_host, proxy_port, tls_proxy, timeout=20):
    """Return a socket already CONNECTed to HOST:443 (or direct)."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)
    if tls_proxy:
        c0 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c0.check_hostname = False
        c0.verify_mode = ssl.CERT_NONE
        s = c0.wrap_socket(s, server_hostname=proxy_host)
    # CONNECT hop. Host header = the relay/tunnel name (relays route by it),
    # CONNECT target = the real Konami endpoint the phone will dial.
    req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n"
           "User-Agent: grpc-c/1.0\r\nConnection: keep-alive\r\n\r\n"
           % (HOST, PORT, proxy_host))
    s.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp and len(resp) < 8192:
        b = s.recv(4096)
        if not b:
            break
        resp += b
    line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
    if " 200" not in line:
        raise RuntimeError("proxy refused: %s %r" % (line, resp[:200]))
    return s


def grpc_once(proxy_host=None, proxy_port=None, tls_proxy=False) -> str:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.maximum_version = ssl.TLSVersion.TLSv1_2
    c.set_alpn_protocols(["grpc-exp", "h2"])
    c.set_ciphers(CIPHERS)
    t0 = time.time()
    try:
        if proxy_host:
            base = raw_connect(proxy_host, proxy_port, tls_proxy)
            s = c.wrap_socket(base, server_hostname=HOST)
        else:
            s = c.wrap_socket(
                socket.create_connection((HOST, 443), timeout=20),
                server_hostname=HOST)
    except Exception as e:
        return "connect-fail %s: %s" % (type(e).__name__, e)
    s.settimeout(20)
    try:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True,
                                             header_encoding="utf-8"))
        conn.initiate_connection()
        conn.send_headers(1, [
            (":method", "POST"), (":scheme", "https"),
            (":authority", HOST), (":path", METHOD),
            ("content-type", "application/grpc"), ("te", "trailers"),
            ("user-agent", "grpc-c/1.0 (android; arm64; pesam)"),
        ], end_stream=False)
        conn.send_data(1, b"\x00\x00\x00\x00\x00", end_stream=True)
        s.sendall(conn.data_to_send())
        out = "no-response"
        end = time.time() + 20
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
                    out = "%.2fs %s g=%s" % (time.time() - t0,
                                             h.get(":status"),
                                             h.get("grpc-status", "-"))
            s.sendall(conn.data_to_send())
            if out != "no-response":
                break
    except Exception as e:
        out = "stream-fail %s: %s" % (type(e).__name__, e)
    finally:
        s.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-host", default=None)
    ap.add_argument("--proxy-port", type=int, default=8080)
    ap.add_argument("--tls-proxy", action="store_true")
    a = ap.parse_args()
    where = ("direct" if not a.proxy_host
             else "via %s:%d%s" % (a.proxy_host, a.proxy_port,
                                   " (tls)" if a.tls_proxy else ""))
    print("probe %s ..." % where, flush=True)
    print("result: %s" % grpc_once(a.proxy_host, a.proxy_port, a.tls_proxy),
          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
