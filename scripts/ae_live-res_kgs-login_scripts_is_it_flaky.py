#!/usr/bin/env python3
"""Is the 502/UNAVAILABLE intermittent?

Sequence of measurements, and why the last conclusion was wrong:

1. `read_grpc_message.py` sent five requests. The ones with
   `content-type: application/grpc` returned 502/14; the one with
   `application/grpc+proto` returned 200 with a real protobuf error. That looked
   conclusive.

2. `ctype_matrix.py` then sent nine more, and `application/grpc` came back
   **200 / grpc-status 13** — the same as `+proto`. So content-type is not the
   discriminator; the 502 is intermittent and the first run happened to catch it
   on the rows that used `application/grpc`.

This measures it properly: the *same* request, byte for byte, N times, counting
the outcomes. If both outcomes appear for identical bytes, the 502 is a
transient load-balancer condition and no request-side change can address it.

It also records the inter-request timing, because a rate limit or a health-check
cycle would show up as a pattern rather than as noise.
"""
from __future__ import annotations

import collections
import socket
import ssl
import sys
import time

sys.path.insert(0, ".")
from decode_capture import hpack_decode  # noqa: E402

HOST = "pes22-game.cs.konami.net"
PORT = 443
PATH = "/command_service.CommandService/CommandStream"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20


def ls(s):
    b = s.encode()
    return bytes([len(b)]) + b


def frame(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def env(msg):
    return b"\x00" + len(msg).to_bytes(4, "big") + msg


def build(msg, ctype="application/grpc"):
    hdrs = (b"\x00" + ls(":method") + ls("POST")
            + b"\x00" + ls(":scheme") + ls("https")
            + b"\x00" + ls(":path") + ls(PATH)
            + b"\x00" + ls(":authority") + ls(HOST)
            + b"\x00" + ls("content-type") + ls(ctype)
            + b"\x00" + ls("te") + ls("trailers"))
    return (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"")
            + frame(1, 0x4, 1, hdrs) + frame(0, 0x1, 1, env(msg)))


def once(payload, settle=4.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=15),
                        server_hostname=HOST)
    t0 = time.time()
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
    return buf, time.time() - t0


def outcome(raw):
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
        j, pad = 0, 0
        if flags & 0x8:
            pad, j = body[0], 1
        try:
            for name, val in hpack_decode(body[j:len(body) - pad], table):
                n = name[0] if isinstance(name, tuple) else name
                v = name[1] if isinstance(name, tuple) else val
                out[n] = v
        except Exception:
            pass
    st = out.get("grpc-status", "-")
    return (out.get(":status", "-"), st, out.get("grpc-message", "-"),
            out.get("content-type", "-"))


def main() -> int:
    payload = build(bytes(range(64)))          # fixed, invalid protobuf
    print("host %s:%d" % (HOST, PORT))
    print("sending %d IDENTICAL requests (content-type: application/grpc)\n"
          % N)
    print("%3s %8s %-7s %-6s %-16s %s"
          % ("#", "dt_ms", ":status", "grpc", "content-type", "message"))
    tally = collections.Counter()
    for i in range(N):
        try:
            raw, dt = once(payload)
            s, g, m, ct = outcome(raw)
        except Exception as e:
            s, g, m, ct = "ERR", type(e).__name__, str(e)[:40], "-"
            dt = 0.0
        key = (s, g)
        tally[key] += 1
        print("%3d %8.0f %-7s %-6s %-16s %s"
              % (i + 1, dt * 1000, s, g, ct, m[:60]))
        time.sleep(0.7)
    print("\n" + "=" * 60)
    for (s, g), c in tally.most_common():
        print("  %3d x  :status=%s grpc-status=%s" % (c, s, g))
    if len(tally) > 1:
        print("\nVERDICT: the SAME bytes produce different outcomes, so the")
        print("502/UNAVAILABLE is INTERMITTENT and is not caused by anything")
        print("in the request. No request-side change can fix it.")
    else:
        print("\nVERDICT: identical bytes gave an identical outcome %d times."
              % N)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
