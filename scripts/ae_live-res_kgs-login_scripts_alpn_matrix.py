#!/usr/bin/env python3
"""Probe how the front door routes, by varying only the ALPN.

The 502 that comes back is `server: awselb/2.0` with `content-length: 0` and
`grpc-status: 14 UNAVAILABLE` -- the request body is never processed, so this
looks like ALB routing rather than the application refusing us.

An ALB can pick a target group from the connection, and ALPN is one of the few
things it has. The game offers ALPN ['grpc-exp', 'h2']; our probe has been
offering ['grpc-exp', 'h2'] too and the server picked 'h2'. So the open
questions are:

  * does the answer change if only 'h2' is offered?
  * what if only 'grpc-exp' is offered?
  * what if HTTP/1.1 is offered instead?
  * what if no ALPN at all is offered?

Everything else -- host, SNI, TLS version, cipher availability, request bytes
-- is held constant, so any difference is attributable to ALPN alone.
"""
from __future__ import annotations

import socket
import ssl
import sys

HOST = "pes22-game.cs.konami.net"
PORT = 443

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def ls(s: str) -> bytes:
    b = s.encode()
    return bytes([len(b)]) + b


def frame(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


H2_REQ = (PREFACE
          + frame(4, 0, 0, b"")
          + frame(1, 0x4, 1,
                  b"\x00" + ls(":method") + ls("POST")
                  + b"\x00" + ls(":scheme") + ls("https")
                  + b"\x00" + ls(":path")
                  + ls("/command_service.CommandService/CommandStream")
                  + b"\x00" + ls(":authority") + ls(HOST)
                  + b"\x00" + ls("content-type") + ls("application/grpc")
                  + b"\x00" + ls("te") + ls("trailers"))
          + frame(0, 0x1, 1, b"\x00\x00\x00\x00\x02\x08\x01"))

H1_REQ = ("POST /command_service.CommandService/CommandStream HTTP/1.1\r\n"
          "Host: %s\r\n"
          "content-type: application/grpc\r\n"
          "te: trailers\r\n"
          "content-length: 7\r\n\r\n"
          "\x00\x00\x00\x00\x02\x08\x01" % HOST).encode()


def probe(alpn, payload, label, tls12=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    if tls12:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except NotImplementedError:
            pass
    out = {"label": label, "alpn_offered": ",".join(alpn) if alpn else "(none)"}
    try:
        raw = socket.create_connection((HOST, PORT), timeout=15)
        s = ctx.wrap_socket(raw, server_hostname=HOST)
        out["tls"] = s.version()
        out["cipher"] = s.cipher()[0]
        out["alpn_chosen"] = s.selected_alpn_protocol()
        s.sendall(payload)
        s.settimeout(6)
        buf = b""
        try:
            while len(buf) < 4096:
                c = s.recv(4096)
                if not c:
                    break
                buf += c
        except socket.timeout:
            pass
        s.close()
        out["bytes"] = len(buf)
        out["hex_head"] = buf[:48].hex()
        # surface anything that names the front door
        low = buf.lower()
        for probe_s in (b"awselb", b"alb", b"envoy", b"nginx", b"html"):
            if probe_s in low:
                out["server_hint"] = probe_s.decode()
                break
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    return out


def show(r):
    print("\n--- %s" % r["label"])
    print("    offered ALPN : %s" % r["alpn_offered"])
    if "error" in r:
        print("    ERROR        : %s" % r["error"])
        return
    print("    TLS          : %s  %s" % (r["tls"], r["cipher"]))
    print("    ALPN chosen  : %s" % r["alpn_chosen"])
    print("    reply        : %d bytes" % r["bytes"])
    if r.get("server_hint"):
        print("    names        : %s" % r["server_hint"])
    print("    head         : %s" % r["hex_head"])


def main() -> int:
    print("host %s:%d  (all variables except ALPN held constant)\n" % (HOST, PORT))
    show(probe(["h2"], H2_REQ, "HTTP/2, ALPN 'h2' only"))
    show(probe(["grpc-exp"], H2_REQ, "HTTP/2 bytes, ALPN 'grpc-exp' only"))
    show(probe(["grpc-exp", "h2"], H2_REQ, "HTTP/2, ALPN 'grpc-exp','h2' (as the game offers)"))
    show(probe(["http/1.1"], H1_REQ, "HTTP/1.1, ALPN 'http/1.1'"))
    show(probe(None, H1_REQ, "HTTP/1.1, no ALPN offered"))
    show(probe(None, H2_REQ, "HTTP/2 bytes, no ALPN offered"))
    print("\nIf every row is byte-identical, ALPN is not the discriminator and the")
    print("difference lies further down the connection (client hello shape, or")
    print("state the ALB associates with the client).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
