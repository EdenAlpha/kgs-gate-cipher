#!/usr/bin/env python3
"""Self-test decode_capture.py on a hand-built HTTP/2 + gRPC + protobuf stream.

If the decoder cannot read a stream whose contents we already know, it cannot
be trusted to read the game's real capture.
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def frame(typ, flags, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([typ, flags])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def hlit_str(s):
    b = s.encode()
    return bytes([len(b)]) + b          # no huffman, 7-bit prefix


def hpack_literal(name, value):
    # 0x00 = literal header field, new name, never indexed
    return (b"\x00" + hlit_str(name) + hlit_str(value))


def varint(v):
    out = b""
    while True:
        x = v & 0x7F
        v >>= 7
        out += bytes([x | (0x80 if v else 0)])
        if not v:
            return out


def pb_varint_field(f, v):
    return varint(f << 3 | 0) + varint(v)


def pb_str_field(f, s):
    b = s.encode()
    return varint(f << 3 | 2) + varint(len(b)) + b


def pb_msg_field(f, payload):
    return varint(f << 3 | 2) + varint(len(payload)) + payload


def main() -> int:
    # a plausible command_service.CommandRequest: version, locale, nested msg
    inner = pb_varint_field(1, 101) + pb_str_field(2, "6.0.1") \
        + pb_str_field(3, "US") + pb_str_field(4, "PES2022")
    msg = pb_varint_field(1, 1) + pb_varint_field(2, 0) + pb_msg_field(9, inner)
    envelope = b"\x00" + len(msg).to_bytes(4, "big") + msg

    hdrs = (hpack_literal(":method", "POST")
            + hpack_literal(":scheme", "https")
            + hpack_literal(":path",
                            "/command_service.CommandService/CommandStream")
            + hpack_literal(":authority", "pes22-game.cs.konami.net")
            + hpack_literal("content-type", "application/grpc")
            + hpack_literal("user-agent", "grpc-c++/1.62.0")
            + hpack_literal("te", "trailers"))

    stream = (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
              + frame(4, 0, 0, struct.pack(">HI", 0x2, 0)          # SETTINGS
                      + struct.pack(">HI", 0x3, 0x10000)
                      + struct.pack(">HI", 0x4, 0x10000000))
              + frame(1, 0x4, 1, hdrs)                              # HEADERS
              + frame(0, 0x1, 1, envelope))                         # DATA+END

    d = tempfile.mkdtemp(prefix="h2self_")
    # split across two "send()" calls, as a real socket would
    with open(os.path.join(d, "frame_1.bin"), "wb") as f:
        f.write(stream[:len(stream) // 2])
    with open(os.path.join(d, "frame_2.bin"), "wb") as f:
        f.write(stream[len(stream) // 2:])

    r = subprocess.run([sys.executable, os.path.join(HERE, "decode_capture.py"), d],
                       capture_output=True, text=True)
    print(r.stdout)
    if r.stderr:
        print("STDERR:", r.stderr)
    ok = (":path: /command_service.CommandService/CommandStream" in r.stdout
          and "content-type: application/grpc" in r.stdout
          and "message_len=%d" % len(msg) in r.stdout
          and "PES2022" in r.stdout)
    print("\nSELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
