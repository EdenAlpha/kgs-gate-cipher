#!/usr/bin/env python3
"""Send the game's own ClientHello bytes to the load balancer and compare the
handshake behaviour against a stock TLS client.

The game's gRPC ClientHello was recovered byte-for-byte from the match exports.
It is genuinely unusual: TLS 1.2 only (no supported_versions at all), five
ciphers (c02b c02c c02f c030 00ff), nine extensions in a fixed order including
one at 0x3374, no padding, no key_share, no psk modes. That is Chromium's Cronet
stack, which also explains Def_Online_Use_Cronet in the binary.

We know the 502 comes with content-length: 0, so the request body is never
processed. That leaves the ClientHello shape as the main thing that differs
between us and the phone.

A ClientHello is sent in the clear, so we can put the game's exact bytes on the
wire without completing a handshake. The question this answers is narrow and
decisive: does the server treat that ClientHello differently at the handshake
stage? We do not need to finish the handshake to find out -- we only need to see
whether a ServerHello comes back, or an alert, or an immediate close.

Rows compared:
  1. the game's exact bytes (fresh random)
  2. the game's exact bytes verbatim, including the captured random
  3. a stock Python TLS 1.2 ClientHello as a control
"""
from __future__ import annotations

import os
import socket
import ssl
import struct
import sys

HOST = "pes22-game.cs.konami.net"
PORT = 443

# Recovered from peerlink_match_*.zip / passthrough_capture.csv.
# 16 0301 00b4 | 01 0000b0 0303 | <32-byte random> | 00 | 000a <ciphers>
# 01 | 007d <extensions>
GAME_HELLO = bytes.fromhex(
    "16030100b4010000b00303ccfa640b200ee97b277f5fb7d5f9204d66211775cb"
    "783803efd4aad1678e138700000ac02bc02cc02fc03000ff0100007d0000001d"
    "001b00001870657332322d67616d652e63732e6b6f6e616d692e6e6574000b00"
    "0403000102000a00040002001700230000337400000010000e000c0867727063"
    "2d6578700268320016000000170000000d002600240403050306030807080808"
    "09080a080b0804080508060401050106010303020303010201"
)


def classify(rec: bytes) -> str:
    if not rec:
        return "nothing (server closed without responding)"
    t = rec[0]
    ver = rec[1:3].hex() if len(rec) >= 3 else "?"
    ln = int.from_bytes(rec[3:5], "big") if len(rec) >= 5 else 0
    if t == 0x16:
        return ("ServerHello / handshake (%d bytes, record ver %s, hs len %d)"
                % (len(rec), ver, ln))
    if t == 0x15:
        lvl, desc = (rec[5], rec[6]) if len(rec) >= 7 else (0, 0)
        return ("ALERT level=%d description=%d  %s"
                % (lvl, desc, ALERTS.get(desc, "?")))
    if t == 0x14:
        return "ChangeCipherSpec"
    return "unexpected record type 0x%02x (%s)" % (t, rec[:16].hex())


ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
          40: "handshake_failure", 42: "bad_certificate",
          43: "unsupported_certificate", 44: "certificate_revoked",
          45: "certificate_expired", 46: "certificate_unknown",
          47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
          50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
          71: "insufficient_security", 80: "internal_error",
          109: "missing_extension", 112: "unrecognized_name",
          120: "no_application_protocol"}


def send_raw(payload: bytes, label: str, timeout=12.0):
    print("\n--- %s" % label)
    print("    sent %d bytes" % len(payload))
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
        s.sendall(payload)
        s.settimeout(timeout)
        buf = b""
        try:
            while len(buf) < 4096:
                c = s.recv(4096)
                if not c:
                    break
                buf += c
                # a ServerHello is enough to know we were accepted
                if buf and buf[0] == 0x16 and len(buf) >= 5:
                    need = 5 + int.from_bytes(buf[3:5], "big")
                    if len(buf) >= need:
                        break
        except socket.timeout:
            pass
        s.close()
    except Exception as e:
        print("    ERROR %s: %s" % (type(e).__name__, e))
        return None
    verdict = classify(buf)
    print("    got  %d bytes" % len(buf))
    print("    ==>  %s" % verdict)
    if buf:
        print("    hex: %s" % buf[:96].hex())
    return buf


def with_fresh_random(hello: bytes) -> bytes:
    """Replace the 32-byte random (offset 11..43) with fresh entropy."""
    return hello[:11] + os.urandom(32) + hello[43:]


def control_python() -> bytes:
    """What a stock Python TLS 1.2 ClientHello produces, and the reply to it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    try:
        s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=12),
                            server_hostname=HOST)
        info = "TLS: %s %s alpn=%s" % (s.version(), s.cipher()[0],
                                       s.selected_alpn_protocol())
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        s.settimeout(5)
        buf = b""
        try:
            buf = s.recv(256)
        except socket.timeout:
            pass
        s.close()
        return buf, info
    except Exception as e:
        return None, "ERROR %s: %s" % (type(e).__name__, e)


def main() -> int:
    print("target %s:%d\n" % (HOST, PORT))
    print("The game's ClientHello, as recovered from the capture:")
    print("  %d bytes, TLS 1.2 only, 5 ciphers, 9 extensions, ALPN grpc-exp,h2\n"
          % len(GAME_HELLO))

    a = send_raw(with_fresh_random(GAME_HELLO),
                 "1. the game's exact ClientHello bytes, fresh random")
    b = send_raw(GAME_HELLO, "2. the game's exact ClientHello bytes, verbatim")
    buf, info = control_python()
    print("\n--- 3. stock Python TLS 1.2 ClientHello (control)")
    print("    handshake: %s" % info)
    print("    ==>  %s" % classify(buf if buf else b""))

    print("\n" + "=" * 70)
    if a is not None and buf is not None:
        same = a[:5] == buf[:5]
        print("game ClientHello  -> %s" % classify(a))
        print("python ClientHello-> %s" % classify(buf))
        print("\nVERDICT: the handshake stage treats them %s"
              % ("IDENTICALLY (so the ClientHello shape is not the discriminator)"
                 if same else
                 "DIFFERENTLY (the ClientHello shape IS the discriminator)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
