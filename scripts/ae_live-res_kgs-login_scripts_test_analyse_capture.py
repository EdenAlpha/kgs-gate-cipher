#!/usr/bin/env python3
"""Self-test analyse_capture.py on a synthetic capture.

The script's whole job is to read `path` out of frames it has never seen, so it
is checked against frames whose contents are known: a stream carrying two
`CommandRequest`s with known paths and payloads, split across three files the
way the send() hook would have written them.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


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


def f_varint(n, v):
    return varint(n << 3 | 0) + varint(v)


def command_request(rid, path, payload, pack=0):
    return (f_str(1, rid) + f_varint(2, pack)
            + f_str(3, payload) + f_str(4, path))


def frame(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def gRPC(msg):
    return b"\x00" + len(msg).to_bytes(4, "big") + msg


def main() -> int:
    d = tempfile.mkdtemp(prefix="anatest_")
    k = os.path.join(d, "kgs")
    os.makedirs(k)

    r1 = command_request("11111111-2222-3333-4444-555555555555",
                         "/session/get", '{"token":"abc"}', 0)
    r2 = command_request("66666666-7777-8888-9999-000000000000",
                         "/room/create", '{"roomType":"1"}', 1)
    r3 = command_request("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                         "/", "{}", 0)

    # A real HPACK block, encoded by the same library the decoder uses. The
    # hand-rolled version of this was deliberately invalid, which meant header
    # extraction was never actually covered -- and the :path is the one header
    # that identifies which of the three commands is being called.
    import hpack
    enc = hpack.Encoder()
    hdrs = enc.encode([
        (":method", "POST"),
        (":scheme", "https"),
        (":path", "/command_service.CommandService/CommandStream"),
        (":authority", "kgs.konami.net"),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("user-agent", "grpc-python/1.0"),
    ])

    blob = (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            + frame(4, 0, 0, b"")
            + frame(1, 0x4, 1, hdrs)
            + frame(0, 0x0, 1, gRPC(r1))
            + frame(0, 0x0, 1, gRPC(r2))
            + frame(0, 0x1, 1, gRPC(r3)))

    # split across three files, as separate send() calls would be
    n = len(blob)
    for i, (a, b) in enumerate(((0, n // 3), (n // 3, 2 * n // 3),
                                (2 * n // 3, n)), start=1):
        with open(os.path.join(k, "frame_%d.bin" % i), "wb") as f:
            f.write(blob[a:b])

    r = subprocess.run([sys.executable, os.path.join(HERE, "analyse_capture.py"),
                        d], capture_output=True, text=True, timeout=120)
    print(r.stdout)
    if r.stderr:
        print("STDERR:", r.stderr[-500:])
    ok = ("/session/get" in r.stdout and "/room/create" in r.stdout
          and '"token":"abc"' in r.stdout and '"roomType":"1"' in r.stdout)
    # the HPACK path must work too, and must report no hpack error
    ok = ok and ":path /command_service.CommandService/CommandStream" in r.stdout
    ok = ok and "hpack:" not in r.stdout
    print("SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
