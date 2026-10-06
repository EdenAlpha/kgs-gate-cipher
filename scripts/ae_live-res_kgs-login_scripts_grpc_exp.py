#!/usr/bin/env python3
"""Talk to the command stream EXACTLY as the app does.

TLS profile, taken byte-for-byte from the app's own ClientHello in
passthrough_capture.csv (flow 10.0.0.2:53370 -> 44.232.213.50:443):
    TLS 1.2 ONLY
    ciphers: ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-GCM-SHA384,
             ECDHE-RSA-AES128-GCM-SHA256,  ECDHE-RSA-AES256-GCM-SHA384,
             TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ALPN offered: ['grpc-exp', 'h2']     (I have only ever offered 'h2')
    ALPN selected by the server is printed below.

Then real HTTP/2 (h2 lib) with gRPC framing, on
    /command_service.CommandService/CommandStream
and the game's own MessagePack body (real_body.bin).
"""
from __future__ import annotations

import os
import socket
import ssl
import struct
import sys

import h2.config
import h2.connection
import h2.events

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
UA = "grpc-c/1.0 (android; arm64; pesam)"

CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")


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


def tls_wrap(sock):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    ctx.set_ciphers(CIPHERS)
    s = ctx.wrap_socket(sock, server_hostname=HOST)
    print("[tls] version=%s cipher=%s alpn=%r"
          % (s.version(), s.cipher(), s.selected_alpn_protocol()), flush=True)
    return s


def run(msgid: str, body: bytes, pack_mode: int, hold: float = 12.0,
        ip: str | None = None) -> None:
    path = "gate/gate_%s.php" % msgid
    payload = command_request(msgid, body, path, pack_mode)
    frame = grpc_frame(payload)
    print("\n=== %s packMode=%d  req=%dB  path=%s  ip=%s ==="
          % (msgid, pack_mode, len(body), path, ip or HOST), flush=True)

    ip = ip or socket.gethostbyname(HOST)
    raw = socket.create_connection((ip, 443), timeout=12)
    s = tls_wrap(raw)
    s.settimeout(hold)

    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding="utf-8"))
    conn.initiate_connection()
    s.sendall(conn.data_to_send())

    conn.send_headers(1, [
        (":method", "POST"), (":scheme", "https"),
        (":authority", HOST), (":path", METHOD),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("user-agent", UA),
        ("grpc-encoding", "identity"),
        ("grpc-accept-encoding", "identity"),
    ], end_stream=False)
    conn.send_data(1, frame, end_stream=False)   # keep the stream OPEN like the app
    s.sendall(conn.data_to_send())

    got, n = [], 0
    try:
        while n < 60:
            data = s.recv(65535)
            if not data:
                break
            n += 1
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    print("  HDRS %s" % dict(ev.headers), flush=True)
                elif isinstance(ev, h2.events.DataReceived):
                    got.append(ev.data)
                    conn.acknowledge_received_data(
                        ev.flow_controlled_length, ev.stream_id)
                    print("  DATA %dB %r" % (len(ev.data), ev.data[:120]),
                          flush=True)
                elif isinstance(ev, h2.events.TrailersReceived):
                    print("  TRAILERS %s" % dict(ev.headers), flush=True)
                elif isinstance(ev, h2.events.StreamEnded):
                    print("  STREAM-ENDED", flush=True)
                elif isinstance(ev, h2.events.StreamReset):
                    print("  RESET %s" % ev.error_code, flush=True)
                elif isinstance(ev, h2.events.WindowUpdated):
                    pass
                elif isinstance(ev, h2.events.PingReceived):
                    conn.ping(b"\x00" * 8)
                elif isinstance(ev, h2.events.RemoteSettingsChanged):
                    print("  SETTINGS-ACK", flush=True)
                else:
                    print("  ev %s" % type(ev).__name__, flush=True)
            out = conn.data_to_send()
            if out:
                s.sendall(out)
            if got and n > 8:
                break
    except socket.timeout:
        print("  (timeout after %d reads -- no answer)" % n, flush=True)
    except Exception as e:
        print("  ERR %s: %s" % (type(e).__name__, str(e)[:80]), flush=True)
    finally:
        s.close()

    blob = b"".join(got)
    if blob:
        for comp, p in decode_frames(blob):
            print("  frame comp=%d len=%d %r" % (comp, len(p), p[:150]),
                  flush=True)
    else:
        print("  no frames", flush=True)


def main() -> int:
    body = open(os.path.join(HERE, "real_body.bin"), "rb").read()
    # the exact addresses the WORKING app used in the user's capture, first
    ips = ["44.232.213.50", "34.208.149.190", "44.255.253.52", None]
    for ip in ips:
        for msgid in ("CMD_GET_SERVER_ENV", "CMD_GET_KGS_GUEST_LOGIN_TOKEN"):
            try:
                run(msgid, body, 1, hold=8.0, ip=ip)
            except Exception as e:
                print("  ERR connect %s: %s"
                      % (type(e).__name__, str(e)[:80]), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
