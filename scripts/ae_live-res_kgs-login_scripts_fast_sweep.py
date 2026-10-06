#!/usr/bin/env python3
"""Fast sweep: which `path` does the server resolve?

The first sweep used a 6 s read timeout, which is 38 minutes for 384 names. The
502 arrives immediately, so 1.2 s is ample; this also reuses a single TLS
connection for many requests where possible, since `CommandStream` is a
bidirectional stream and the game pipelines on one.

Any path that does NOT come back as `grpc-status: 14 UNAVAILABLE` is a real
command, and the response is printed in full.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import struct
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode_capture import hpack_decode  # noqa: E402
from kgs_client import HOST, PORT, RPC, command_request, command_response  # noqa: E402

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"


def fr(t, f, sid, body):
    return (len(body).to_bytes(3, "big") + bytes([t, f])
            + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)


def ls(s):
    b = s.encode()
    return bytes([len(b)]) + b


def open_stream():
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
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + fr(4, 0, 0, b"")
              + fr(1, 0x4, 1, hdrs))
    return s


def drain(s, settle=1.2):
    """Read whatever is available; return (status, message, data_bytes)."""
    s.settimeout(settle)
    st, gm, data = None, "", b""
    table = []
    try:
        while True:
            buf = s.recv(32768)
            if not buf:
                break
            i = 0
            while i + 9 <= len(buf):
                ln = int.from_bytes(buf[i:i + 3], "big")
                if i + 9 + ln > len(buf):
                    break
                typ, flags = buf[i + 3], buf[i + 4]
                body = buf[i + 9:i + 9 + ln]
                i += 9 + ln
                if typ == 0:
                    data += body
                elif typ == 1:
                    j, pad = 0, 0
                    if flags & 0x8:
                        pad, j = body[0], 1
                    try:
                        for name, val in hpack_decode(body[j:len(body) - pad],
                                                      table):
                            n = name[0] if isinstance(name, tuple) else name
                            v = name[1] if isinstance(name, tuple) else val
                            if n == "grpc-status":
                                st = v
                            elif n == "grpc-message":
                                gm = unquote_plus(v)
                    except Exception:
                        pass
                    if st is not None:
                        return st, gm, data
            if i < len(buf):                       # partial frame: keep it
                s.settimeout(settle)
    except socket.timeout:
        pass
    return st, gm, data


def main() -> int:
    d = open(SO, "rb").read()
    names = sorted(set(m.group(0).decode()
                       for m in re.finditer(rb"CMD_[A-Z0-9_]{2,48}", d)))
    print("sweeping %d CMD_* names\n" % len(names), flush=True)
    resolved = []
    s = open_stream()
    done = 0
    try:
        for p in names:
            try:
                m = command_request(str(uuid.uuid4()), p, "{}", 0)
                s.sendall(fr(0, 0x0, 1, b"\x00" + len(m).to_bytes(4, "big") + m))
                st, gm, data = drain(s)
            except Exception as e:
                print("  %-34s CONNECTION LOST (%s) - reopening" % (p, e), flush=True)
                try:
                    s.close()
                except Exception:
                    pass
                s = open_stream()
                continue
            done += 1
            if st is None:
                # A timeout is NOT a resolution. An earlier version of this
                # script tested `st != "14"`, which counted every timeout as a
                # hit and printed 384 false "RESOLVED" lines. Only an actual
                # status counts.
                print("  %-34s -> NO STATUS (timeout, not a result)" % p,
                      flush=True)
            elif st != "14":
                print("  %-34s -> grpc=%-4s data=%-4d %s   <<< RESOLVED"
                      % (p, st, len(data), gm[:70]), flush=True)
                resolved.append((p, st, gm, data))
                if data and len(data) >= 5:
                    mlen = int.from_bytes(data[1:5], "big")
                    dec = command_response(data[5:5 + mlen])
                    print("        CommandResponse: %s" % dec, flush=True)
            if done % 40 == 0:
                print("     ...%d/%d, %d resolved" % (done, len(names),
                                                      len(resolved)), flush=True)
                if resolved:
                    break
    finally:
        try:
            s.close()
        except Exception:
            pass
    print("\nswept %d, RESOLVED %d: %s"
          % (done, len(resolved), [r[0] for r in resolved]), flush=True)
    if not resolved:
        print("No CMD_* name resolves. `path` is not a command enum name; it is\n"
              "most likely a URL path. The remaining source for the real value\n"
              "is the game's own request bytes.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
