#!/usr/bin/env python3
"""Find the `path` value, now that we know it lives in field 2.

What the oracle established (scripts/find_schema.py):

  * a length-delimited field in slot 2 changes the failure mode, so slot 2 is
    the one the server reads;
  * anything without it returns `grpc-status: 14 UNAVAILABLE`, which the load
    balancer renders as HTTP 502. So `502/14` never meant "unhealthy target" --
    it meant "the application could not resolve the command".

This sweeps candidate `path` values in field 2 and looks for a response that is
neither 14 (unresolved) nor 13 (we sent something unparseable) -- i.e. one that
means the command was recognised.
"""
from __future__ import annotations

import socket
import ssl
import sys
from urllib.parse import unquote_plus

sys.path.insert(0, ".")
from decode_capture import hpack_decode  # noqa: E402

HOST = "pes22-game.cs.konami.net"
PORT = 443
RPC = "/command_service.CommandService/CommandStream"


def varint(v):
    out = b""
    while True:
        x = v & 0x7F
        v >>= 7
        out += bytes([x | (0x80 if v else 0)])
        if not v:
            return out


def f_str(n, s):
    b = s.encode()
    return varint(n << 3 | 2) + varint(len(b)) + b


def f_bytes(n, b):
    return varint(n << 3 | 2) + varint(len(b)) + b


def f_varint(n, v):
    return varint(n << 3 | 0) + varint(v)


def ls(s):
    b = s.encode()
    return bytes([len(b)]) + b


def frame(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def h2(msg, ctype="application/grpc+proto"):
    hdrs = (b"\x00" + ls(":method") + ls("POST")
            + b"\x00" + ls(":scheme") + ls("https")
            + b"\x00" + ls(":path") + ls(RPC)
            + b"\x00" + ls(":authority") + ls(HOST)
            + b"\x00" + ls("content-type") + ls(ctype)
            + b"\x00" + ls("te") + ls("trailers"))
    g = b"\x00" + len(msg).to_bytes(4, "big") + msg
    return (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"")
            + frame(1, 0x4, 1, hdrs) + frame(0, 0x1, 1, g))


def send(msg, settle=4.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=15),
                        server_hostname=HOST)
    s.sendall(h2(msg))
    s.settimeout(settle)
    buf = b""
    try:
        while len(buf) < 32768:
            c = s.recv(32768)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    s.close()
    return parse(buf)


def parse(raw):
    i, out, table, frames = 0, {}, [], []
    while i + 9 <= len(raw):
        ln = int.from_bytes(raw[i:i + 3], "big")
        typ, flags = raw[i + 3], raw[i + 4]
        body = raw[i + 9:i + 9 + ln]
        if i + 9 + ln > len(raw):
            break
        i += 9 + ln
        frames.append((typ, flags, body))
        if typ == 0 and body:
            out.setdefault("data", b"")
            out["data"] += body
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
    out["_frames"] = frames
    return out


def show(label, msg):
    try:
        h = send(msg)
    except Exception as e:
        print("  %-46s -> ERROR %s: %s" % (label, type(e).__name__, e))
        return None
    st = h.get("grpc-status", "-")
    gm = unquote_plus(h.get("grpc-message", "-"))
    print("  %-46s -> http=%-4s grpc=%-4s %s"
          % (label, h.get(":status", "-"), st, gm[:88]))
    if h.get("data"):
        print("        data(%d): %s" % (len(h["data"]), h["data"][:48].hex()))
    return h


CANDIDATES = [
    "CMD_GET_SESSION_ID", "CMD_LOGIN", "CMD_CREATEJOIN_ROOM",
    "GetSessionId", "Login", "getSessionId", "get_session_id",
    "command_service.CommandRequest",
    "command_service.CommandService/CommandStream",
    "efootball.v1.CommandService", "KGS", "kgs",
    "/CMD_GET_SESSION_ID", "pes22-game",
]


def main() -> int:
    print("host %s:%d\n" % (HOST, RPC and PORT))
    print("A. empty request, for reference")
    show("(empty)", b"")

    print("\nB. path in field 2, various command names, no req payload")
    for p in CANDIDATES:
        show("f2=%r" % p, f_str(2, p))

    print("\nC. path in field 2 plus an empty req in field 3")
    for p in CANDIDATES[:6]:
        show("f2=%r + f3=''" % p, f_str(2, p) + f_bytes(3, b""))

    print("\nD. packMode in field 1 (0=JSON, 1=MSGPACK) with a path in field 2")
    for pm in (0, 1):
        for p in CANDIDATES[:4]:
            show("f1=%d f2=%r" % (pm, p), f_varint(1, pm) + f_str(2, p))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
