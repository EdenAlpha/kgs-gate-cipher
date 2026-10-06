#!/usr/bin/env python3
"""Proper bidirectional gRPC CommandStream client over raw HTTP/2.

The endpoint answered with grpc-status:14 (UNAVAILABLE) to a unary POST.
CommandStream is bidi (client_streaming=1, server_streaming=1), so we must
keep the stream open and exchange many frames.  Uses the `h2` library to
drive a real HTTP/2 connection.

Protocol (decoded from the embedded command_service.proto):

  CommandRequest  { id = msgid, packMode, req = <payload>, path }
  CommandResponse { id, packMode, res = <payload> }
"""
from __future__ import annotations

import socket
import ssl
import struct
import sys
import time

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
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


def command_request(msgid: str, body: bytes, path: str, pack_mode: int = 1):
    out = enc_str(1, msgid)
    out += bytes([2 << 3 | 0]) + enc_varint(pack_mode)
    out += enc_str(3, body)
    out += enc_str(4, path)
    return out


def grpc_frame(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def decode_frames(data: bytes):
    out, i = [], 0
    while i + 5 <= len(data):
        ln = struct.unpack(">I", data[i + 1:i + 5])[0]
        out.append((data[i], data[i + 5:i + 5 + ln]))
        i += 5 + ln
    return out


def show_payload(payload: bytes, indent: str = "        "):
    """Decode CommandResponse { id=1, packMode=2, res=3 }."""
    i = 0
    while i < len(payload):
        key = payload[i]
        fno, wt = key >> 3, key & 7
        i += 1
        if wt == 0:
            v = sh = 0
            while i < len(payload):
                c = payload[i]
                i += 1
                v |= (c & 0x7F) << sh
                if not (c & 0x80):
                    break
                sh += 7
            print(f"{indent}f{fno} varint {v}", flush=True)
        elif wt == 2:
            n = sh = 0
            while i < len(payload):
                c = payload[i]
                i += 1
                n |= (c & 0x7F) << sh
                if not (c & 0x80):
                    break
                sh += 7
            raw = payload[i:i + n]
            i += n
            print(f"{indent}f{fno} bytes[{n}] {raw[:200]!r}", flush=True)
        else:
            break


def main() -> int:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    sock = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=30),
                           server_hostname=HOST)
    print(f"[grpc] connected  alpn={sock.selected_alpn_protocol()}", flush=True)

    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    headers = [
        (":method", "POST"), (":scheme", "https"), (":authority", HOST),
        (":path", METHOD),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("user-agent", UA),
        ("grpc-encoding", "identity"),
        ("grpc-accept-encoding", "identity"),
    ]
    stream = 1
    conn.send_headers(stream, headers, end_stream=False)
    sock.sendall(conn.data_to_send())

    # ---- the sequence the app uses --------------------------------------
    seq = [
        ("CMD_CONNECT_GRPC", b"", "gate/gate_CMD_CONNECT_GRPC.php"),
        ("CMD_GET_SERVER_ENV", BODY, "gate/gate_CMD_GET_SERVER_ENV.php"),
        ("CMD_GET_KGS_GUEST_LOGIN_TOKEN", BODY,
         "gate/gate_CMD_GET_KGS_GUEST_LOGIN_TOKEN.php"),
        ("CMD_LOGIN", BODY, "gate/gate_CMD_LOGIN.php"),
    ]

    for i, (msgid, body, path) in enumerate(seq):
        req = command_request(msgid, body, path, 1)
        conn.send_data(stream, grpc_frame(req), end_stream=False)
        sock.sendall(conn.data_to_send())
        print(f"\n[grpc] >>> {msgid}  ({len(req)}B)  path={path}", flush=True)

        # collect any response for up to 6s
        sock.settimeout(6)
        try:
            while True:
                data = sock.recv(65535)
                if not data:
                    print("    (connection closed)", flush=True)
                    return 0
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.ResponseReceived):
                        print("    headers: " + str(
                            {k: v for k, v in ev.headers}), flush=True)
                    elif isinstance(ev, h2.events.DataReceived):
                        chunk = ev.data
                        conn.acknowledge_received_data(
                            ev.flow_controlled_length, ev.stream_id)
                        for comp, payload in decode_frames(chunk):
                            print(f"    <<< frame comp={comp} "
                                  f"{len(payload)}B", flush=True)
                            show_payload(payload)
                    elif isinstance(ev, h2.events.TrailersReceived):
                        print("    trailers: " + str(
                            {k: v for k, v in ev.headers}), flush=True)
                    elif isinstance(ev, h2.events.StreamEnded):
                        print("    stream ended", flush=True)
                    elif isinstance(ev, h2.events.StreamReset):
                        print(f"    STREAM RESET error={ev.error_code}",
                              flush=True)
                        return 1
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
        except socket.timeout:
            print("    (no reply within 6s -- keeping stream open)",
                  flush=True)
        except Exception as e:
            print(f"    ERR {type(e).__name__}: {e}", flush=True)
            break

    # close cleanly
    try:
        conn.end_stream(stream)
        sock.sendall(conn.data_to_send())
    except Exception:
        pass
    print("\n[grpc] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
