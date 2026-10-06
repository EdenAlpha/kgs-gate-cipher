#!/usr/bin/env python3
"""Open the stream the way the app does: CMD_CONNECT_GRPC FIRST.

Every probe so far fired CMD_GET_SERVER_ENV (or others) as the first and only
message on a fresh stream.  If the server holds per-stream state that only
CMD_CONNECT_GRPC creates, it drops/closes anything else -> ALB sees the
backend close -> HTTP 502.  That matches every observation (instant 502,
healthy targets, phone works).

So: bidi stream, CONNECT first, keep the send side OPEN (the app never
half-closes; it keepalives every ~15 s), read, then ENV on the same stream.
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


def req(msgid: str) -> pb.CommandRequest:
    return pb.CommandRequest(
        id=msgid, packMode=pb.PACK_MODE_MSGPACK, req=body(msgid),
        path="gate/gate_%s.php" % msgid)


def main() -> int:
    creds = grpc.ssl_channel_credentials()
    ch = grpc.secure_channel(HOST, creds)
    stub = rpc.CommandServiceStub(ch)

    import time
    outstanding = [req("CMD_CONNECT_GRPC")]
    sent_connect = False

    def gen():
        deadline = time.time() + 50
        while time.time() < deadline:
            if outstanding:
                m = outstanding.pop(0)
                print("  >> sending %s" % m.id, flush=True)
                yield m
            else:
                time.sleep(0.2)
        return

    try:
        call = stub.CommandStream(gen(), timeout=60)
        n = 0
        for resp in call:
            n += 1
            print("  << id=%r packMode=%s res=%dB %r"
                  % (resp.id, resp.packMode, len(resp.res),
                     resp.res[:300]), flush=True)
            if n == 1:
                outstanding.append(req("CMD_GET_SERVER_ENV"))
            if n >= 4:
                break
        print("  stream ok, %d responses" % n, flush=True)
    except grpc.RpcError as e:
        print("  RPC %s: %s" % (e.code(), e.details()[:200]), flush=True)
    ch.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
