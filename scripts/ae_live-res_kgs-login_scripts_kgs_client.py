#!/usr/bin/env python3
"""A correct command_service client, built from the schema in the binary.

Parsed out of libUE4.so's embedded FileDescriptorProto
(scripts/descriptor2.py), not inferred:

    message CommandRequest {
        string   id       = 1;
        PackMode packMode = 2;   // 0 = JSON, 1 = MSGPACK
        string   req      = 3;   // a STRING: the payload as text
        string   path     = 4;   // the command name
    }
    message CommandResponse {
        string id = 1;  PackMode packMode = 2;  string res = 3;
    }
    rpc CommandStream(stream CommandRequest) returns (stream CommandResponse);

`path` is field 4. Every earlier attempt put it in the wrong slot -- or omitted
it -- and an unresolvable command is what the application reports as
`grpc-status: 14 UNAVAILABLE`, which the load balancer renders as HTTP 502.
That was the whole of the 502/14.

This sends a well-formed CommandRequest and prints whatever comes back, so the
command names can be discovered from the server's own answers.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode_capture import hpack_decode  # noqa: E402

HOST = "pes22-game.cs.konami.net"
PORT = 443
RPC = "/command_service.CommandService/CommandStream"
PACK_JSON, PACK_MSGPACK = 0, 1


# ------------------------------------------------------------------ protobuf
def varint(v: int) -> bytes:
    out = b""
    while True:
        x = v & 0x7F
        v >>= 7
        out += bytes([x | (0x80 if v else 0)])
        if not v:
            return out


def f_str(n: int, s: str) -> bytes:
    b = s.encode("utf-8")
    return varint(n << 3 | 2) + varint(len(b)) + b


def f_varint(n: int, v: int) -> bytes:
    return varint(n << 3 | 0) + varint(v)


def command_request(req_id: str, path: str, payload: str,
                    pack_mode: int = PACK_JSON) -> bytes:
    """CommandRequest{id=1, packMode=2, req=3, path=4}."""
    return (f_str(1, req_id)
            + f_varint(2, pack_mode)
            + f_str(3, payload)
            + f_str(4, path))


def varint_read(b, i):
    v, shift = 0, 0
    while i < len(b):
        x = b[i]
        v |= (x & 0x7F) << shift
        i += 1
        if not (x & 0x80):
            break
        shift += 7
    return v, i


def command_response(b: bytes):
    """Decode CommandResponse{id=1, packMode=2, res=3}."""
    out = {}
    i = 0
    while i < len(b):
        key, i = varint_read(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 2:
            ln, i = varint_read(b, i)
            v = b[i:i + ln]
            i += ln
            if fn == 1:
                out["id"] = v.decode("utf-8", "replace")
            elif fn == 3:
                out["res"] = v.decode("utf-8", "replace")
            else:
                out.setdefault("other", {})[fn] = v.hex()
        elif wt == 0:
            v, i = varint_read(b, i)
            if fn == 2:
                out["packMode"] = v
        else:
            return out
    return out


# ------------------------------------------------------------------- h2/gRPC
def ls(s: str) -> bytes:
    b = s.encode()
    return bytes([len(b)]) + b


def frame(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def connect():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=20),
                        server_hostname=HOST)
    hdrs = (b"\x00" + ls(":method") + ls("POST")
            + b"\x00" + ls(":scheme") + ls("https")
            + b"\x00" + ls(":path") + ls(RPC)
            + b"\x00" + ls(":authority") + ls(HOST)
            + b"\x00" + ls("content-type") + ls("application/grpc+proto")
            + b"\x00" + ls("te") + ls("trailers"))
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"")
              + frame(1, 0x4, 1, hdrs))
    return s


def read_frames(s, settle=6.0, want_data=1):
    """Read until we have `want_data` DATA payloads or the stream ends."""
    s.settimeout(settle)
    buf = b""
    out = {"headers": [], "data": b"", "closed": False, "raw_len": 0}
    table = []
    got = 0
    try:
        while got < want_data:
            c = s.recv(32768)
            if not c:
                out["closed"] = True
                break
            buf += c
            i = 0
            while i + 9 <= len(buf):
                ln = int.from_bytes(buf[i:i + 3], "big")
                if i + 9 + ln > len(buf):
                    break
                typ, flags = buf[i + 3], buf[i + 4]
                body = buf[i + 9:i + 9 + ln]
                i += 9 + ln
                if typ == 0 and body:
                    out["data"] += body
                    got += 1
                elif typ == 1:
                    j, pad = 0, 0
                    if flags & 0x8:
                        pad, j = body[0], 1
                    h = {}
                    try:
                        for name, val in hpack_decode(body[j:len(body) - pad],
                                                      table):
                            n = name[0] if isinstance(name, tuple) else name
                            v = name[1] if isinstance(name, tuple) else val
                            h[n] = v
                    except Exception:
                        pass
                    out["headers"].append((flags, h))
                    if h.get(":status") and int(h.get(":status", 0)) != 200:
                        out["closed"] = True
            buf = buf[i:]
            if out["closed"]:
                break
    except socket.timeout:
        pass
    out["raw_len"] = sum(len(h) for _f, h in out["headers"])
    return out


def call(path, payload="{}", pack_mode=PACK_JSON, req_id=None, settle=6.0):
    req_id = req_id or str(uuid.uuid4())
    msg = command_request(req_id, path, payload, pack_mode)
    s = connect()
    try:
        g = b"\x00" + len(msg).to_bytes(4, "big") + msg
        s.sendall(frame(0, 0x1, 1, g))
        r = read_frames(s, settle)
    finally:
        try:
            s.close()
        except Exception:
            pass
    r["sent"] = msg
    r["id"] = req_id
    return r


def report(path, payload="{}", pack_mode=PACK_JSON):
    try:
        r = call(path, payload, pack_mode)
    except Exception as e:
        print("  %-34s -> ERROR %s: %s" % (path, type(e).__name__, e))
        return None
    st = "-"
    gm = ""
    for flags, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = unquote_plus(h.get("grpc-message", ""))
    data = r["data"]
    inner = ""
    if len(data) >= 5:
        mlen = int.from_bytes(data[1:5], "big")
        body = data[5:5 + mlen]
        dec = command_response(body)
        inner = " id=%s packMode=%s res=%r" % (dec.get("id"),
                                                dec.get("packMode"),
                                                (dec.get("res") or "")[:120])
    print("  %-34s -> grpc=%-4s %s%s"
          % (path[:34], st, gm[:70], inner))
    return r


def main() -> int:
    print("host %s:%d" % (HOST, PORT))
    print("CommandRequest{id=1, packMode=2, req=3, path=4}\n")

    print("A. sanity: a well-formed request with a plausible path")
    for p in ("CMD_GET_SESSION_ID", "GetSessionId", "CMD_LOGIN", "Login"):
        report(p, "{}", PACK_JSON)

    print("\nB. same, packMode = MSGPACK")
    for p in ("CMD_GET_SESSION_ID", "CMD_LOGIN"):
        report(p, "{}", PACK_MSGPACK)

    print("\nC. a deliberately unknown path, as a control")
    report("this_command_does_not_exist", "{}", PACK_JSON)

    print("\nD. full request bytes for the first case, for the record")
    r = call("CMD_GET_SESSION_ID", "{}", PACK_JSON)
    print("  sent %d bytes: %s" % (len(r["sent"]), r["sent"].hex()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
