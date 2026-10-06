#!/usr/bin/env python3
"""Replay the game's own captured bytes at Konami, verbatim, over TLS.

This is the step that turns a capture into an answer. Once capture_insecure.js
has handed us the exact HTTP/2 byte stream the game's gRPC stack produced, we
send those *same bytes* -- preface, SETTINGS, HEADERS (with the game's real
HPACK encoding and dynamic-table state), DATA -- over a real TLS connection to
the real endpoint.

Two possible outcomes, both decisive:

  * the server answers normally  -> the difference was in the request bytes,
    and diffing this stream against what our probes build localises it;
  * it answers 502 g=14          -> the request bytes are NOT the problem, so
    the difference is in the transport (TLS fingerprint / connection setup),
    which is the other half of the investigation.

Nothing is reconstructed: the payload is a byte-for-byte copy.
"""
from __future__ import annotations

import argparse
import glob
import os
import socket
import ssl
import sys

DEFAULT_HOST = "pes22-game.cs.konami.net"
DEFAULT_PORT = 443


def load_frames(d: str) -> bytes:
    files = sorted(glob.glob(os.path.join(d, "frame_*.bin")),
                   key=lambda p: int(p.rsplit("_", 1)[1].split(".")[0]))
    if not files:
        sys.exit("no frame_*.bin in %s" % d)
    blob = b"".join(open(f, "rb").read() for f in files)
    return blob


def describe(blob: bytes) -> None:
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    print("payload: %d bytes from the game's own gRPC stack" % len(blob))
    print("starts with h2 preface: %s"
          % ("yes" if blob.startswith(preface) else "NO"))
    i = len(preface) if blob.startswith(preface) else 0
    TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
             4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
             8: "WINDOW_UPDATE", 9: "CONTINUATION"}
    while i + 9 <= len(blob):
        ln = int.from_bytes(blob[i:i + 3], "big")
        typ = blob[i + 3]
        flg = blob[i + 4]
        sid = int.from_bytes(blob[i + 5:i + 9], "big") & 0x7FFFFFFF
        if i + 9 + ln > len(blob):
            print("  (truncated at offset %d)" % i)
            break
        print("  %-13s len=%-6d stream=%-3d flags=%#04x"
              % (TYPES.get(typ, "TYPE%d" % typ), ln, sid, flg))
        i += 9 + ln


def read_response(sock, limit=262144, timeout=20.0, settle=3.0) -> bytes:
    """Read until the peer stops sending for `settle` seconds, or we time out.

    Reading only one frame is not enough: the server's SETTINGS/WINDOW_UPDATE
    arrive immediately, and the answer that matters is the response to our
    request, which follows.
    """
    import time
    sock.settimeout(settle)
    out = b""
    deadline = time.time() + timeout
    last = time.time()
    while len(out) < limit and time.time() < deadline:
        try:
            chunk = sock.recv(16384)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
        last = time.time()
        # a complete response for a gRPC unary call ends with trailers
        if len(out) >= 9:
            i, frames = 0, []
            while i + 9 <= len(out):
                ln = int.from_bytes(out[i:i + 3], "big")
                frames.append((out[i + 3], out[i + 4], ln))
                i += 9 + ln
            if i == len(out) and len(frames) >= 3:
                types = [f[0] for f in frames]
                # SETTINGS + (HEADERS|DATA) ... and something END_STREAM
                if 4 in types and any(t in (0, 1) for t in types) \
                        and any(f[1] & 0x1 for f in frames):
                    break
    return out


def summarise_response(raw: bytes) -> None:
    print("\n--- %d bytes back ---" % len(raw))
    if not raw:
        print("empty (connection closed with no data)")
        return
    # the game-side 502 has been seen as a gRPC trailers-only response, i.e. an
    # HTTP/2 HEADERS frame carrying :status 502. Decode the first frame's
    # static-table indices so we can read :status straight out of HPACK.
    if len(raw) >= 9 and (raw[3] & 0x80):
        ln = int.from_bytes(raw[0:3], "big")
        typ, flg = raw[3], raw[4]
        sid = int.from_bytes(raw[5:9], "big") & 0x7FFFFFFF
        print("first frame: type=%d len=%d stream=%d flags=%#04x" % (typ, ln, sid, flg))
        body = raw[9:9 + ln]
        print("body hex: %s" % body[:96].hex())
        # indexed header field with static index 8 == :status 200,
        # and 0x88 with an 8-bit prefix carrying a 4xx/5xx code
        if body and body[0] == 0x88:
            print(">>> :status %d" % (body[1] % 256))
        elif body and (body[0] & 0xE0) == 0x20:
            print(">>> dynamic table size update")
        if flg & 0x5:
            print(">>> end-stream/headers: this is a trailers-only or final "
                  "response for the request")
    else:
        print("raw: %s" % raw[:160].hex())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", help="directory holding frame_*.bin")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--ip", default=None,
                    help="connect to this IP but keep SNI/authority")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    blob = load_frames(a.dir)
    describe(blob)
    if a.dry_run:
        return 0

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    # match the client's own ALPN choice
    try:
        ctx.set_alpn_protocols(["grpc-exp", "h2"])
    except NotImplementedError:
        pass

    target = a.ip or a.host
    print("\nconnecting to %s (%s:443), SNI/verify against %s ..."
          % (target, a.host, a.host))
    raw = socket.create_connection((target, a.port), timeout=20)
    s = ctx.wrap_socket(raw, server_hostname=a.host)
    print("TLS: %s  cipher=%s  alpn=%s"
          % (s.version(), s.cipher()[0], s.selected_alpn_protocol()))

    s.sendall(blob)
    print("sent %d bytes (the game's own frames, unmodified)" % len(blob))
    resp = read_response(s)
    try:
        s.close()
    except Exception:
        pass
    summarise_response(resp)
    with open(os.path.join(a.dir, "replay_response.bin"), "wb") as f:
        f.write(resp)
    print("\nresponse written to %s"
          % os.path.join(a.dir, "replay_response.bin"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
