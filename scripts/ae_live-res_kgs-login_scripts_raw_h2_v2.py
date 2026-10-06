#!/usr/bin/env python3
"""Raw HTTP/2 gRPC probe, tuned like grpc-c actually behaves.

Differences from the python-h2 probe that just changed the server's answer:
  * hand-built frames with literal (non-Huffman) HPACK
  * do NOT close the request stream (grpc bidi streams stay open)
  * wait for the server's SETTINGS before sending the request
  * honour the server's initial window; send WINDOW_UPDATE for what we read
  * drain HEADERS/DATA/GOAWAY/RST_STREAM until a real answer or timeout
"""
from __future__ import annotations

import socket
import ssl
import struct
import sys
import time

import hpack
import msgpack

sys.path.insert(0, r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work")
import probe_game_ip as P  # noqa: E402
from raw_h2_probe import HOST, IP, PREFACE, frame, headers_block  # noqa: E402

UA = "grpc-c/1.0 (android; arm64; pesam)"
PATH = "/command_service.CommandService/CommandStream"


def settings_frame() -> bytes:
    body = struct.pack(">HI", 3, 100) + struct.pack(">HI", 4, 4194304)
    return frame(0x4, 0, 0, body)


def read_frames(sock, dec, seconds=10.0):
    sock.settimeout(seconds)
    buf = b""
    try:
        while True:
            d = sock.recv(8192)
            if not d:
                return buf, "closed-by-server"
            buf += d
    except socket.timeout:
        return buf, "timeout"
    except ssl.SSLError as e:
        return buf, "sslerr %s" % e


def walk(buf, dec):
    out = []
    o = 0
    while o + 9 <= len(buf):
        ln = int.from_bytes(buf[o:o + 3], "big")
        ftype, flags = buf[o + 3], buf[o + 4]
        sid = int.from_bytes(buf[o + 5:o + 9], "big") & 0x7FFFFFFF
        pay = buf[o + 9:o + 9 + ln]
        rec = {"type": ftype, "flags": flags, "sid": sid, "len": ln}
        if ftype in (1, 9) and pay:
            try:
                rec["headers"] = dec.decode(pay)
            except Exception as e:
                rec["hpack_err"] = str(e)
        if ftype == 0 and pay:
            rec["data"] = pay
        if ftype == 3 and len(pay) >= 4:
            rec["rst"] = int.from_bytes(pay[0:4], "big")
        if ftype == 7:
            rec["goaway_last"] = int.from_bytes(pay[0:4], "big") if len(pay) >= 4 else None
            rec["goaway_code"] = int.from_bytes(pay[4:8], "big") if len(pay) >= 8 else None
        out.append(rec)
        o += 9 + ln
    return out


def env_body(msgid: str) -> bytes:
    d = {"msgid": msgid, "rqid": 0,
         "user_id": "3c5aad3c6b8425c611ebe2f5da6c25af",
         "session_id": "", "my_platform": "Android", "s_keyword": "",
         "lang": "US", "region": "US", "platform": "Android",
         "client_version": "6.0.1"}
    return msgpack.packb(d, use_bin_type=True)


def probe(tag: str, msgid: str, keep_open: bool, wait_settings: bool,
          ua: str = UA) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    s = ctx.wrap_socket(socket.create_connection((IP, 443), timeout=20),
                        server_hostname=HOST)
    dec = hpack.Decoder()
    s.sendall(PREFACE + settings_frame())

    if wait_settings:
        buf, why = read_frames(s, dec, 4.0)
        print("  [%s] pre-request: %s (%dB)" % (tag, why, len(buf)), flush=True)
        for r in walk(buf, dec):
            print("     %s" % r, flush=True)

    msg = P.request(msgid, env_body(msgid), "gate/gate_%s.php" % msgid, 1)
    data = frame(0x0, 0x0 if keep_open else 0x1, 1, P.frame(msg))
    s.sendall(frame(0x1, 0x4, 1, headers_block(HOST, PATH, ua)) + data)

    buf, why = read_frames(s, dec, 10.0)
    print("[%s] %s (%dB)" % (tag, why, len(buf)), flush=True)
    for r in walk(buf, dec):
        print("   ", r, flush=True)
        if r["type"] in (1, 9) and r.get("headers"):
            for k, v in r["headers"]:
                if k in (":status", "grpc-status", "grpc-message", "server"):
                    print("        %s: %s" % (k, v), flush=True)
    s.close()


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "a"):
        probe("A keep-open + wait-SETTINGS", "CMD_GET_SESSION_ID", True, True)
    if which in ("all", "b"):
        probe("B keep-open no-wait", "CMD_GET_SESSION_ID", True, False)
    if which in ("all", "c"):
        probe("C end-stream + wait-SETTINGS", "CMD_GET_SESSION_ID", False, True)
