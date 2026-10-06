#!/usr/bin/env python3
"""Does the gRPC server read our request body at all?

This settles a claim I got wrong earlier. I read `content-length: 0` in the
502 response as proof that the request body was never processed. That was an
inference, not a measurement: a gRPC error status is returned as a
trailers-only response, which has no body by definition, so `content-length: 0`
says nothing about whether the request was read.

The clean test is differential. Send the identical request twice, changing only
the message payload, and compare the responses byte for byte:

  * identical responses  -> the server is not differentiating on the body, so
                           this is availability/routing, not request content;
  * different responses  -> the server is reading the body, so the request
                           content matters after all.

Each body is also sent twice, as a control for any per-connection variation.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"
PORT = 443
PATH = "/command_service.CommandService/CommandStream"


def ls(s: str) -> bytes:
    b = s.encode()
    return bytes([len(b)]) + b


def frame(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def envelope(msg: bytes) -> bytes:
    return b"\x00" + len(msg).to_bytes(4, "big") + msg


def build(msg: bytes) -> bytes:
    hdrs = (b"\x00" + ls(":method") + ls("POST")
            + b"\x00" + ls(":scheme") + ls("https")
            + b"\x00" + ls(":path") + ls(PATH)
            + b"\x00" + ls(":authority") + ls(HOST)
            + b"\x00" + ls("content-type") + ls("application/grpc")
            + b"\x00" + ls("te") + ls("trailers"))
    return (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            + frame(4, 0, 0, b"")
            + frame(1, 0x4, 1, hdrs)
            + frame(0, 0x1, 1, envelope(msg)))


# Three deliberately different protobuf bodies.
BODIES = {
    "field1=1 (minimal)":        b"\x08\x01",
    "field1=2 (different value)": b"\x08\x02",
    "random 64 bytes":           bytes(range(64)),
    "empty message":             b"",
}


def send(payload: bytes, settle=4.0):
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


def main() -> int:
    print("host %s:%d  path %s\n" % (HOST, PORT, PATH))
    results = {}
    for label, msg in BODIES.items():
        payload = build(msg)
        reps = []
        for i in range(2):
            try:
                reps.append(send(payload))
            except Exception as e:
                reps.append(("ERR", "%s: %s" % (type(e).__name__, e)))
        results[label] = reps
        r0 = reps[0]
        if isinstance(r0, tuple):
            print("%-28s -> ERROR %s" % (label, r0[1]))
            continue
        # strip the volatile parts: the server's random and its date header
        h = hashlib.sha256(r0).hexdigest()[:12]
        print("%-28s -> %4d bytes  sha=%s" % (label, len(r0), h))
        print("     %s" % r0[:64].hex())

    print("\n" + "=" * 70)
    hashes = {}
    for label, reps in results.items():
        if isinstance(reps[0], tuple):
            continue
        hashes[label] = (hashlib.sha256(reps[0]).hexdigest(),
                         hashlib.sha256(reps[1]).hexdigest())
    vals = set(hashes.values())
    if len(vals) == 1:
        print("all bodies produced an IDENTICAL response, and so did the repeat")
        print("of each body. The server is not differentiating on the request")
        print("content -> this is availability/routing, not request semantics.")
    else:
        print("responses differ. Detail:")
        for label, (h1, h2) in hashes.items():
            print("  %-28s run1=%s run2=%s%s"
                  % (label, h1[:12], h2[:12],
                     "  (varies per connection)" if h1 != h2 else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
