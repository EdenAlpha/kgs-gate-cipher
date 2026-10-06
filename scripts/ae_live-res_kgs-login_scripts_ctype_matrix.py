#!/usr/bin/env python3
"""Confirm the content-type discriminator, and map what the server accepts.

read_grpc_message.py found the decisive difference:

    content-type: application/grpc        -> 502, grpc-status 14 "unavailable"
    content-type: application/grpc+proto  -> 200, grpc-status 13, and a real
                                             protobuf parse error

So `application/grpc` never reaches the application, and every request we ever
sent used it. That is the whole reason 50+ variants produced an identical
answer: the load balancer was answering before the gRPC server was involved.

This walks the content-type space (and a few neighbours) to find exactly where
the boundary is, so the fix is precise rather than a guess.
"""
from __future__ import annotations

import socket
import ssl
import sys

sys.path.insert(0, ".")
from decode_capture import hpack_decode  # noqa: E402

HOST = "pes22-game.cs.konami.net"
PORT = 443
PATH = "/command_service.CommandService/CommandStream"


def ls(s):
    b = s.encode()
    return bytes([len(b)]) + b


def frame(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def env(msg):
    return b"\x00" + len(msg).to_bytes(4, "big") + msg


def build(msg, ctype, extra=None):
    hdrs = (b"\x00" + ls(":method") + ls("POST")
            + b"\x00" + ls(":scheme") + ls("https")
            + b"\x00" + ls(":path") + ls(PATH)
            + b"\x00" + ls(":authority") + ls(HOST)
            + b"\x00" + ls("content-type") + ls(ctype)
            + b"\x00" + ls("te") + ls("trailers"))
    if extra:
        for k, v in extra:
            hdrs += b"\x00" + ls(k) + ls(v)
    return (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"")
            + frame(1, 0x4, 1, hdrs) + frame(0, 0x1, 1, env(msg)))


def send(payload, settle=4.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=15),
                        server_hostname=HOST)
    s.sendall(payload)
    s.settimeout(settle)
    buf = b""
    try:
        while len(buf) < 16384:
            c = s.recv(16384)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    s.close()
    return buf


def summarise(raw):
    """Pull :status, grpc-status and grpc-message out of the response."""
    i, out, table = 0, {}, []
    while i + 9 <= len(raw):
        ln = int.from_bytes(raw[i:i + 3], "big")
        typ, flags = raw[i + 3], raw[i + 4]
        body = raw[i + 9:i + 9 + ln]
        if i + 9 + ln > len(raw):
            break
        i += 9 + ln
        if typ != 1:
            continue
        j = 0
        pad = 0
        if flags & 0x8:
            pad = body[0]
            j = 1
        try:
            for name, val in hpack_decode(body[j:len(body) - pad], table):
                n = name[0] if isinstance(name, tuple) else name
                v = name[1] if isinstance(name, tuple) else val
                out[n] = v
        except Exception:
            pass
    return out


def main() -> int:
    # a body that is definitely invalid protobuf, so a server that parses it
    # always tells us so -- the clearest possible "I got your request" signal
    probe = bytes(range(64))

    cases = [
        ("application/grpc", None),
        ("application/grpc+proto", None),
        ("application/grpc;", None),
        ("application/grpc+json", None),
        ("application/grpc-proto", None),
        ("APPLICATION/GRPC+PROTO", None),
        ("application/grpc+proto; charset=utf-8", None),
        ("application/grpc+proto", [("user-agent", "grpc-c++/1.62.0")]),
        ("application/grpc+proto", [("grpc-accept-encoding", "identity")]),
    ]
    print("host %s:%d   path %s\n" % (HOST, PORT, PATH))
    print("probe body: 64 bytes of invalid protobuf\n")
    print("%-40s %-6s %-14s %s" % ("content-type", ":status", "grpc-status",
                                   "grpc-message"))
    for ctype, extra in cases:
        try:
            raw = send(build(probe, ctype, extra))
        except Exception as e:
            print("%-40s ERROR %s: %s" % (ctype, type(e).__name__, e))
            continue
        h = summarise(raw)
        extra_s = ""
        if extra:
            extra_s = "  +" + ",".join(k for k, _ in extra)
        print("%-40s %-6s %-14s %s%s"
              % (ctype, h.get(":status", "-"), h.get("grpc-status", "-"),
                 h.get("grpc-message", "-"), extra_s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
