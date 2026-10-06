#!/usr/bin/env python3
"""Probe the gRPC endpoint's routing and auth requirements.

grpc-status:14 (UNAVAILABLE) from awselb/2.0 means the ALB has a gRPC target
group but the backend is not reachable to us.  Try:
  1. different :authority values (ALB routes on Host)
  2. grpc-timeout metadata
  3. initial metadata the app might send
  4. the grpc health check service
  5. other gRPC paths
"""
from __future__ import annotations

import socket
import ssl
import struct

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
UA = "grpc-c/1.0 (android; arm64; pesam)"


def grpc_call(path: str, authority: str, extra_headers=None,
              payload: bytes = b"", end_stream: bool = True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    sock = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=15),
                           server_hostname=HOST)
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    headers = [
        (":method", "POST"), (":scheme", "https"), (":authority", authority),
        (":path", path),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("user-agent", UA),
    ]
    if extra_headers:
        headers.extend(extra_headers)

    conn.send_headers(1, headers, end_stream=False)
    if payload:
        conn.send_data(1, b"\x00" + struct.pack(">I", len(payload)) + payload,
                       end_stream=end_stream)
    else:
        conn.send_data(1, b"", end_stream=end_stream)
    sock.sendall(conn.data_to_send())

    sock.settimeout(10)
    result = {"status": None, "grpc_status": None, "grpc_message": None,
              "server": None, "body": b"", "trailers": {}}
    try:
        while True:
            data = sock.recv(65535)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    d = {k: v for k, v in ev.headers}
                    result["status"] = d.get(":status")
                    result["grpc_status"] = d.get("grpc-status")
                    result["grpc_message"] = d.get("grpc-message")
                    result["server"] = d.get("server")
                elif isinstance(ev, h2.events.DataReceived):
                    result["body"] += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length,
                                                   ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    result["trailers"] = {k: v for k, v in ev.headers}
                elif isinstance(ev, h2.events.StreamEnded):
                    break
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
            if result["status"]:
                break
    except Exception:
        pass
    sock.close()
    return result


def show(label: str, r: dict) -> None:
    tag = ""
    if r["grpc_status"] and r["grpc_status"] != "14":
        tag = "   <<<<<< NOT UNAVAILABLE"
    if r["grpc_message"] and r["grpc_message"] != "unavailable":
        tag = "   <<<<<< DIFFERENT"
    if r["status"] and r["status"] != "502":
        tag = "   <<<<<< NOT 502"
    print(f"  {label:52s} :status={r['status']} "
          f"grpc-status={r['grpc_status']} "
          f"grpc-message={r['grpc_message']}  "
          f"server={r['server']}  body={len(r['body'])}B{tag}", flush=True)
    if r["trailers"]:
        print(f"      trailers: {r['trailers']}", flush=True)
    if r["body"]:
        print(f"      body: {r['body'][:200]!r}", flush=True)


print("=== gRPC path + authority probe ===", flush=True)

PATHS = [
    "/command_service.CommandService/CommandStream",
    "/command_service.CommandService/Command",
    "/grpc.health.v1.Health/Check",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/command_service/CommandStream",
    "/CommandService/CommandStream",
]

for p in PATHS:
    show(f"path={p}", grpc_call(p, HOST))

print("\n=== authority variants (ALB routes on Host) ===", flush=True)
for auth in (HOST, "pes22-game", "grpc.pes22-game.cs.konami.net",
             "pes22-grpc.cs.konami.net", "localhost", HOST + ":443"):
    show(f"authority={auth}",
         grpc_call("/command_service.CommandService/CommandStream", auth))

print("\n=== with app-like metadata ===", flush=True)
META = [
    [("grpc-timeout", "10S")],
    [("authorization", "Bearer guest")],
    [("x-konami-client", "pes22/6.0.1")],
    [("grpc-encoding", "gzip")],
    [("content-type", "application/grpc+proto")],
    [("content-type", "application/grpc+json")],
]
for meta in META:
    label = meta[0][0] + "=" + meta[0][1][:20]
    show(label,
         grpc_call("/command_service.CommandService/CommandStream", HOST,
                   extra_headers=meta))
