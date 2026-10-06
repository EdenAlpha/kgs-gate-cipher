#!/usr/bin/env python3
"""Recover the CommandRequest wire format using the server as an oracle.

The schema is known from the embedded descriptor's string table:

    message CommandRequest  { string path; PackMode packMode; bytes req; }
    message CommandResponse { PackMode packMode; bytes res; }
    enum PackMode { PACK_MODE_JSON = 0; PACK_MODE_MSGPACK = 1; }

but the field *numbers* are varints inside the descriptor blob, not in the string
table, and that blob references its strings indirectly so it could not be read
directly.

The server will tell us instead. When a message parses, it fails later with a
message about the *contents*; when it does not parse, it fails immediately with
a wire-format complaint. So: put a candidate field in each slot, send it, and
watch which candidates change the error. The one that moves the error is the
right slot.
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


def varint(v):
    out = b""
    while True:
        x = v & 0x7F
        v >>= 7
        out += bytes([x | (0x80 if v else 0)])
        if not v:
            return out


def f_varint(n, v):
    return varint(n << 3 | 0) + varint(v)


def f_len(n, b):
    return varint(n << 3 | 2) + varint(len(b)) + b


def f_str(n, s):
    return f_len(n, s.encode())


def ls(s):
    b = s.encode()
    return bytes([len(b)]) + b


def frame(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def env(msg):
    return b"\x00" + len(msg).to_bytes(4, "big") + msg


def h2(msg, ctype="application/grpc+proto", extra=()):
    hdrs = (b"\x00" + ls(":method") + ls("POST")
            + b"\x00" + ls(":scheme") + ls("https")
            + b"\x00" + ls(":path") + ls(PATH)
            + b"\x00" + ls(":authority") + ls(HOST)
            + b"\x00" + ls("content-type") + ls(ctype)
            + b"\x00" + ls("te") + ls("trailers"))
    for k, v in extra:
        hdrs += b"\x00" + ls(k) + ls(v)
    return (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"")
            + frame(1, 0x4, 1, hdrs) + frame(0, 0x1, 1, env(msg)))


def send(msg, extra=(), settle=4.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=15),
                        server_hostname=HOST)
    s.sendall(h2(msg, extra=extra))
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
    return parse(buf)


def parse(raw):
    i, out, table = 0, {}, []
    while i + 9 <= len(raw):
        ln = int.from_bytes(raw[i:i + 3], "big")
        typ, flags = raw[i + 3], raw[i + 4]
        body = raw[i + 9:i + 9 + ln]
        if i + 9 + ln > len(raw):
            break
        i += 9 + ln
        if typ == 0 and body:
            out["#data"] = body
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
    return out


def show(label, msg, extra=()):
    try:
        h = send(msg, extra)
    except Exception as e:
        print("  %-44s -> ERROR %s" % (label, e))
        return None
    st = h.get("grpc-status", "-")
    gm = h.get("grpc-message", "-")
    try:
        from urllib.parse import unquote_plus
        gm = unquote_plus(gm)
    except Exception:
        pass
    print("  %-44s -> status=%-4s grpc=%-4s %s"
          % (label, h.get(":status", "-"), st, gm[:90]))
    if "#data" in h:
        print("        response data: %s" % h["#data"].hex())
    return h


def main() -> int:
    print("host %s:%d\n" % (HOST, PORT))

    print("A. baseline -- an empty CommandRequest")
    show("empty message", b"")

    print("\nB. which field number is `path` (a string)?")
    for n in (1, 2, 3, 4, 5):
        show("field %d = string \"TEST\"" % n, f_str(n, "TEST"))

    print("\nC. which field number is `packMode` (an enum varint)?")
    for n in (1, 2, 3, 4, 5):
        show("field %d = varint 1 (MSGPACK)" % n, f_varint(n, 1))

    print("\nD. which field number is `req` (bytes / msgpack)?")
    # msgpack map {"a":1} = 0x81 0xa1 0x61 0x01
    mp = bytes.fromhex("81a16101")
    for n in (1, 2, 3, 4, 5):
        show("field %d = bytes 81a16101 (msgpack map)" % n, f_len(n, mp))

    print("\nE. combined guesses, using the most likely layout")
    for order in ((1, 2, 3), (2, 1, 3), (1, 3, 2), (3, 1, 2)):
        msg = (f_str(order[0], "test") + f_varint(order[1], 1)
               + f_len(order[2], mp))
        show("path=%d packMode=%d req=%d" % order, msg)

    print("\nF. what does the server want `path` to be? try real command names")
    for p in ("CMD_GET_SESSION_ID", "GetSessionId", "get_session_id",
              "command_service.CommandRequest"):
        show("path=%r" % p, f_str(1, p) + f_varint(2, 1) + f_len(3, mp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
