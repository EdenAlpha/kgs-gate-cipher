#!/usr/bin/env python3
"""Talk to the command stream with the REAL gRPC C core (grpcio).

Same library family as the app's built-in grpc-c: real HTTP/2 behavior,
real framing, real trailers.  If this 502s too, the transport fingerprint
is eliminated and only message content / server state remains.
"""
from __future__ import annotations

import os
import sys

import grpc
import msgpack

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import command_service_pb2 as pb
import command_service_pb2_grpc as rpc

HOST = "pes22-game.cs.konami.net:443"
UID = "3c5aad3c6b8425c611ebe2f5da6c25af"
VER = "6.0.1"


def body(msgid: str) -> bytes:
    return msgpack.packb(
        {"msgid": msgid, "rqid": 0, "user_id": UID, "session_id": "",
         "my_platform": "Android", "s_keyword": "", "lang": "US",
         "region": "US", "platform": "Android", "client_version": VER},
        use_bin_type=True)


def main() -> int:
    creds = grpc.ssl_channel_credentials()
    opts = [
        ("grpc.primary_user_agent", "grpc-c/1.0 (android; arm64; pesam)"),
        ("grpc.ssl_cipher_suites",
         "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
         "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"),
    ]
    ch = grpc.secure_channel(HOST, creds, options=opts)
    stub = rpc.CommandServiceStub(ch)

    def gen():
        for msgid in ("CMD_GET_SERVER_ENV", "CMD_GET_KGS_GUEST_LOGIN_TOKEN"):
            print("  >> sending %s" % msgid, flush=True)
            yield pb.CommandRequest(
                id=msgid, packMode=pb.PACK_MODE_MSGPACK,
                req=body(msgid), path="gate/gate_%s.php" % msgid)

    try:
        for resp in stub.CommandStream(gen(), timeout=25):
            print("  << id=%r packMode=%s res=%dB %r"
                  % (resp.id, resp.packMode, len(resp.res),
                     resp.res[:200]), flush=True)
    except grpc.RpcError as e:
        print("  RPC %s: %s" % (e.code(), e.details()[:200]), flush=True)
    ch.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
