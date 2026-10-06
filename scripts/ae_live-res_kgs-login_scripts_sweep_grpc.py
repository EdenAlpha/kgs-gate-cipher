#!/usr/bin/env python3
"""gRPC against EVERY IP pes22-game.cs.konami.net resolves to, right now.

All gRPC probes so far hit 3-4 addresses (44.232.213.50, 34.208.149.190,
44.255.253.52 + resolver pick).  DNS rotates across 8-9 addresses and the
phone may be on a healthy one while we keep drawing broken ones.  The gate
sweep covered 18 IPs but only for HTTPS-POST; gRPC was never swept.
"""
from __future__ import annotations

import os
import socket
import sys

import grpc
import msgpack

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import command_service_pb2 as pb
import command_service_pb2_grpc as rpc

HOST = "pes22-game.cs.konami.net"
UID = "3c5aad3c6b8425c611ebe2f5da6c25af"
VER = "6.0.1"


def body(msgid: str) -> bytes:
    return msgpack.packb(
        {"msgid": msgid, "rqid": 0, "user_id": UID, "session_id": "",
         "my_platform": "Android", "s_keyword": "", "lang": "US",
         "region": "US", "platform": "Android", "client_version": VER},
        use_bin_type=True)


def probe(ip: str) -> str:
    creds = grpc.ssl_channel_credentials()
    # connect to the IP but speak for the hostname (SNI + authority)
    ch = grpc.secure_channel(
        "%s:443" % ip,
        creds,
        options=[("grpc.ssl_target_name_override", HOST),
                 ("grpc.default_authority", HOST)])
    stub = rpc.CommandServiceStub(ch)

    def gen():
        yield pb.CommandRequest(
            id="CMD_GET_SERVER_ENV", packMode=pb.PACK_MODE_MSGPACK,
            req=body("CMD_GET_SERVER_ENV"),
            path="gate/gate_CMD_GET_SERVER_ENV.php")

    try:
        for resp in stub.CommandStream(gen(), timeout=12):
            ch.close()
            return "ANSWER id=%r res=%dB %r" % (
                resp.id, len(resp.res), resp.res[:120])
    except grpc.RpcError as e:
        return "RPC %s %s" % (e.code(), (e.details() or "")[:60])
    finally:
        ch.close()
    return "no response"


def main() -> int:
    infos = socket.getaddrinfo(HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
    ips = sorted({i[4][0] for i in infos})
    print("today: %d addresses: %s" % (len(ips), " ".join(ips)), flush=True)
    for ip in ips:
        try:
            print("  %-16s %s" % (ip, probe(ip)), flush=True)
        except Exception as e:
            print("  %-16s ERR %s: %s" % (ip, type(e).__name__,
                                          str(e)[:70]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
