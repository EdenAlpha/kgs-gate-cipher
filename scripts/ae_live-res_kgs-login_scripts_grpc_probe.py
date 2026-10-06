#!/usr/bin/env python3
"""Speak the app's real protocol: gRPC CommandStream over HTTP/2.

    POST /command_service.CommandService/CommandStream
    content-type: application/grpc
    te: trailers
    body: <5-byte gRPC frame> <protobuf CommandRequest>

CommandRequest { id = msgid, packMode = PACK_MODE_MSGPACK, req = body,
                 path = "gate/gate_<msgid>.php" }

Every value comes from the game: the body from its serializer (real_body.bin),
the msgid and path conventions from its own composer.  curl_cffi gives us a
real HTTP/2 connection (the same transport the app's gRPC uses).
"""
from __future__ import annotations

import struct
import sys

from curl_cffi import requests

HOST = "https://pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
UA = "grpc-c/1.0 (android; arm64; pesam)"

BODY = open("real_body.bin", "rb").read()      # the game's own MessagePack


def enc_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_str(field: int, s) -> bytes:
    raw = s.encode() if isinstance(s, str) else bytes(s)
    return bytes([field << 3 | 2]) + enc_varint(len(raw)) + raw


def command_request(msgid: str, body: bytes, path: str,
                    pack_mode: int = 1) -> bytes:
    out = b""
    out += enc_str(1, msgid)                    # id
    out += bytes([2 << 3 | 0]) + enc_varint(pack_mode)   # packMode
    out += enc_str(3, body)                     # req (raw bytes as string)
    out += enc_str(4, path)                     # path
    return out


def grpc_frame(payload: bytes) -> bytes:
    """1-byte compression flag + 4-byte big-endian length."""
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def decode_frames(data: bytes):
    out, i = [], 0
    while i + 5 <= len(data):
        comp = data[i]
        ln = struct.unpack(">I", data[i + 1:i + 5])[0]
        out.append((comp, data[i + 5:i + 5 + ln]))
        i += 5 + ln
    return out


def try_one(msgid: str, pack_mode: int, label: str) -> None:
    path = f"gate/gate_{msgid}.php"
    req = command_request(msgid, BODY, path, pack_mode)
    frame = grpc_frame(req)
    print(f"\n=== {msgid}  packMode={pack_mode}  {label} ===", flush=True)
    print(f"    CommandRequest ({len(req)}B) id={msgid!r} path={path!r} "
          f"req={len(BODY)}B", flush=True)
    try:
        r = requests.post(
            HOST + METHOD,
            data=frame,
            headers={
                "content-type": "application/grpc",
                "te": "trailers",
                "user-agent": UA,
                "grpc-encoding": "identity",
                "grpc-accept-encoding": "identity",
            },
            impersonate="chrome131",
            timeout=30,
            verify=False,
        )
    except Exception as e:
        print(f"    ERR {type(e).__name__}: {e}", flush=True)
        return
    print(f"    HTTP {r.status_code}  headers=", flush=True)
    for k, v in r.headers.items():
        if k.lower().startswith("grpc") or k.lower() in (
                "content-type", "trailer", "date"):
            print(f"        {k}: {v}", flush=True)
    body = r.content or b""
    print(f"    body {len(body)}B {body[:200]!r}", flush=True)
    for comp, payload in decode_frames(body):
        print(f"      frame comp={comp} len={len(payload)} "
              f"{payload[:150]!r}", flush=True)
        # CommandResponse { id=1, packMode=2, res=3 }
        i = 0
        while i < len(payload):
            key = payload[i]
            fno, wt = key >> 3, key & 7
            i += 1
            if wt == 0:
                v = 0
                sh = 0
                while i < len(payload):
                    c = payload[i]
                    i += 1
                    v |= (c & 0x7F) << sh
                    if not (c & 0x80):
                        break
                    sh += 7
                print(f"          f{fno} varint {v}", flush=True)
            elif wt == 2:
                n = 0
                sh = 0
                while i < len(payload):
                    c = payload[i]
                    i += 1
                    n |= (c & 0x7F) << sh
                    if not (c & 0x80):
                        break
                    sh += 7
                raw = payload[i:i + n]
                i += n
                print(f"          f{fno} bytes[{n}] {raw[:120]!r}", flush=True)
            else:
                break


def main() -> int:
    for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN",
                  "CMD_GET_KGS_GUEST_LOGIN_TOKEN"):
        try_one(msgid, 1, "msgpack")
    try_one("CMD_GET_SERVER_ENV", 0, "json mode")
    return 0


if __name__ == "__main__":
    sys.exit(main())
