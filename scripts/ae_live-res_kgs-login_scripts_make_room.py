#!/usr/bin/env python3
"""Create the room and print the code.

Chain (from the binary's own msgid table, 384 commands):
    CMD_LOGIN                      -> session
    CMD_GET_SESSION_ID             -> session_id for the body fields
    CMD_CREATEJOIN_ROOM            -> room
    CMD_GET_ROOM_INFO              -> the room's code
    CMD_SEND_RECRUIT_CODE          -> recruit/share code (the join code)

Runs the same gRPC transport as gate_retry.py (TLS 1.2, 5 ciphers,
ALPN grpc-exp+h2, /command_service.CommandService/CommandStream) and the real
identity values from the user's capture.

Usage:
    python make_room.py                 # run the whole chain
    python make_room.py CMD_GET_ROOM_INFO   # single command
"""
from __future__ import annotations

import os
import struct
import sys

import h2.config
import h2.connection
import h2.events
import msgpack

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from gate_retry import (CIPHERS, HOST, METHOD, UA, VER,  # noqa: E402
                        command_request, grpc_frame)

UID = "3c5aad3c6b8425c611ebe2f5da6c25af"

# extra fields the room commands need (values come from CMD_GET_SESSION_ID /
# CMD_LOGIN responses -- filled in as we get them)
SESSION_ID = ""
ROOM_ID = ""


def body(msgid: str, extra: dict | None = None) -> bytes:
    d = {"msgid": msgid, "rqid": 0, "user_id": UID,
         "session_id": SESSION_ID, "my_platform": "Android",
         "s_keyword": "", "lang": "US", "region": "US",
         "platform": "Android", "client_version": VER}
    if extra:
        d.update(extra)
    return msgpack.packb(d, use_bin_type=True)


def grpc_call(msgid: str, payload: bytes, hold: float = 15.0) -> dict:
    import socket
    import ssl

    path = "gate/gate_%s.php" % msgid
    frame = grpc_frame(command_request(msgid, payload, path))
    ip = socket.gethostbyname(HOST)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    ctx.set_ciphers(CIPHERS)
    s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=15),
                        server_hostname=HOST)
    s.settimeout(hold)

    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding="utf-8"))
    conn.initiate_connection()
    conn.send_headers(1, [
        (":method", "POST"), (":scheme", "https"), (":authority", HOST),
        (":path", METHOD), ("content-type", "application/grpc"),
        ("te", "trailers"), ("user-agent", UA),
        ("grpc-encoding", "identity"), ("grpc-accept-encoding", "identity"),
    ], end_stream=False)
    conn.send_data(1, frame, end_stream=True)
    s.sendall(conn.data_to_send())

    data, hdrs = [], {}
    try:
        while True:
            chunk = s.recv(65535)
            if not chunk:
                break
            for ev in conn.receive_data(chunk):
                if isinstance(ev, h2.events.ResponseReceived):
                    hdrs = dict(ev.headers)
                elif isinstance(ev, h2.events.DataReceived):
                    data.append(ev.data)
                elif isinstance(ev, h2.events.StreamEnded):
                    s.close()
                    return {"hdrs": hdrs, "body": b"".join(data)}
            s.sendall(conn.data_to_send())
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return {"hdrs": hdrs, "body": b"".join(data)}


def frames(blob: bytes):
    out, i = [], 0
    while i + 5 <= len(blob):
        ln = struct.unpack(">I", blob[i + 1:i + 5])[0]
        out.append(blob[i + 5:i + 5 + ln])
        i += 5 + ln
    return out


def show(msgid: str, r: dict) -> bytes:
    hdrs = r.get("hdrs", {})
    print("  %s -> %s" % (msgid, hdrs), flush=True)
    res = b""
    for p in frames(r.get("body", b"")):
        print("    frame %dB %r" % (len(p), p[:300]), flush=True)
        res += p
    return res


CHAIN = [
    ("CMD_GET_SESSION_ID", {"game_id": UID}),
    ("CMD_LOGIN", {}),
    ("CMD_CREATEJOIN_ROOM", {"room_name": "peerlink",
                             "room_comment": "", "max_user": 2,
                             "password": "", "match_mode": 0}),
    ("CMD_GET_ROOM_INFO", {"room_id": ROOM_ID}),
    ("CMD_SEND_RECRUIT_CODE", {"room_id": ROOM_ID}),
]

# response fields (xref'd from the game's own response parsers):
#   CMD_CREATEJOIN_ROOM   -> result, room_id, event_log
#   CMD_SEND_RECRUIT_CODE -> recruit_code        (the join code for the user)
#   CMD_GET_SESSION_ID    -> needs 'game_id' in the REQUEST


def main() -> int:
    global SESSION_ID, ROOM_ID
    if len(sys.argv) > 1:
        msgid = sys.argv[1]
        show(msgid, grpc_call(msgid, body(msgid)))
        return 0
    for msgid, extra in CHAIN:
        if extra.get("room_id") == "" and "room_id" in extra:
            extra = {k: v for k, v in extra.items() if k != "room_id"}
        try:
            res = show(msgid, grpc_call(msgid, body(msgid, extra)))
            if b"session_id" in res:
                SESSION_ID = res[:80].decode("latin1", "replace")
            if b"room" in res and not ROOM_ID:
                ROOM_ID = res[:80].decode("latin1", "replace")
        except Exception as e:
            print("  %s ERR %s: %s" % (msgid, type(e).__name__,
                                       str(e)[:80]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
