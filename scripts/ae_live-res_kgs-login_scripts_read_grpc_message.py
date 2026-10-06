#!/usr/bin/env python3
"""Read the gRPC error messages the server returns for different bodies.

body_differs.py showed the response changes with the request payload -- a
71-byte body produced a 134-byte HEADERS frame where a 5-byte body produced
87. That means the server parses our message, so the useful next step is simply
to read what it says.

Each response is a trailers-only HEADERS frame, so the whole thing decodes to a
handful of headers including grpc-status and grpc-message.
"""
from __future__ import annotations

import socket
import ssl
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) if False else ".")
from decode_capture import TYPES, FLAGS, hpack_decode, fl  # noqa: E402

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


def build(msg):
    hdrs = (b"\x00" + ls(":method") + ls("POST")
            + b"\x00" + ls(":scheme") + ls("https")
            + b"\x00" + ls(":path") + ls(PATH)
            + b"\x00" + ls(":authority") + ls(HOST)
            + b"\x00" + ls("content-type") + ls("application/grpc")
            + b"\x00" + ls("te") + ls("trailers"))
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


def show(raw, label):
    print("\n" + "=" * 70)
    print("### %s" % label)
    i = 0
    table = []
    while i + 9 <= len(raw):
        ln = int.from_bytes(raw[i:i + 3], "big")
        typ, flags = raw[i + 3], raw[i + 4]
        sid = int.from_bytes(raw[i + 5:i + 9], "big") & 0x7FFFFFFF
        body = raw[i + 9:i + 9 + ln]
        if i + 9 + ln > len(raw):
            break
        i += 9 + ln
        tag = TYPES.get(typ, "TYPE%d" % typ)
        print("  %-13s len=%-5d stream=%d flags=%s" % (tag, ln, sid, fl(flags)))
        if typ == 1:
            j = 0
            pad = 0
            if flags & 0x8:
                pad = body[0]
                j = 1
            if flags & 0x20:
                j += 5
            try:
                for name, val in hpack_decode(body[j:len(body) - pad], table):
                    n = name[0] if isinstance(name, tuple) else name
                    v = name[1] if isinstance(name, tuple) else val
                    print("      %-22s %s" % (n, v))
            except SystemExit as e:
                print("      hpack: %s" % e)
            except Exception as e:
                print("      hpack error: %s" % e)
        elif typ == 0 and body:
            print("      data: %s" % body.hex())
        elif typ == 4 and not (flags & 0x100) and body:
            for k in range(0, len(body) - 5, 6):
                print("      setting 0x%04x = %d"
                      % (int.from_bytes(body[k:k + 2], "big"),
                         int.from_bytes(body[k + 2:k + 6], "big")))


CASES = [
    ("empty message (5 B on the wire)", b""),
    ("field 1 = 1", b"\x08\x01"),
    ("field 1 = 2  (different value)", b"\x08\x02"),
    ("64 bytes of junk (not valid protobuf)", bytes(range(64))),
    ("valid protobuf, 200 bytes", b"\x08\x01" + b"\x12" + b"\xc8\x01"
     + b"A" * 200),
]


def main() -> int:
    print("host %s:%d\n" % (HOST, PORT))
    for label, msg in CASES:
        try:
            raw = send(build(msg))
        except Exception as e:
            print("\n### %s -> ERROR %s: %s" % (label, type(e).__name__, e))
            continue
        show(raw, label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
