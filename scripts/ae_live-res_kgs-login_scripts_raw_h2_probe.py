#!/usr/bin/env python3
"""Raw HTTP/2 probe: hand-built frames, literal (non-Huffman) HPACK, exactly
like grpc-c/BoringSSL writes them. If the backend's HTTP/2 parser rejects
Huffman-coded or otherwise "odd" header blocks, it drops the stream and the
ALB answers 502/14 -- which is precisely what our python-h2 probe always got.
"""
from __future__ import annotations

import socket
import ssl
import struct
import sys

import msgpack

sys.path.insert(0, r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work")
import probe_game_ip as P  # noqa: E402

HOST = "pes22-game.cs.konami.net"
IP = "54.203.69.122"
PATH = "/command_service.CommandService/CommandStream"

# ---- HPACK: indexed + literal-without-huffman (no dynamic table use) -------
STATIC = {
    1: ":authority", 2: ":method", 3: ":scheme", 4: ":path", 6: ":protocol",
    8: ":status",
}


def lit(name: str, value: str, never: bool = True) -> bytes:
    """Literal header field without indexing, no Huffman (0x00 prefix)."""
    def enc_str(s: str) -> bytes:
        raw = s.encode()
        return bytes([len(raw)]) + raw
    return b"\x00" + enc_str(name) + enc_str(value)


def headers_block(authority: str, path: str, ua: str) -> bytes:
    out = bytearray()
    out += b"\x82"                                   # indexed :method POST
    out += b"\x87"                                   # indexed :scheme https
    out += lit(":authority", authority)
    out += lit(":path", path)
    out += lit("content-type", "application/grpc")
    out += lit("te", "trailers")
    out += lit("user-agent", ua)
    out += lit("grpc-encoding", "identity")
    out += lit("grpc-accept-encoding", "identity")
    return bytes(out)


def frame(ftype: int, flags: int, sid: int, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack(">I", sid) + payload)


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def settings() -> bytes:
    body = struct.pack(">HI", 3, 100) + struct.pack(">HI", 4, 4194304)
    return frame(0x4, 0, 0, body)


def env_body(msgid: str) -> bytes:
    d = {"msgid": msgid, "rqid": 0,
         "user_id": "3c5aad3c6b8425c611ebe2f5da6c25af",
         "session_id": "", "my_platform": "Android", "s_keyword": "",
         "lang": "US", "region": "US", "platform": "Android",
         "client_version": "6.0.1"}
    return msgpack.packb(d, use_bin_type=True)


def go(tag: str, msgid: str, ua: str, with_settings: bool = True,
       ack_window: bool = True) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    s = ctx.wrap_socket(socket.create_connection((IP, 443), timeout=20),
                        server_hostname=HOST)
    s.sendall(PREFACE + (settings() if with_settings else b""))
    hb = headers_block(HOST, PATH, ua)
    s.sendall(frame(0x1, 0x4 | 0x1, 1, hb)          # END_HEADERS|END_STREAM
              if False else
              frame(0x1, 0x4, 1, hb))               # END_HEADERS, stream open
    msg = P.request(msgid, env_body(msgid),
                    "gate/gate_%s.php" % msgid, 1)
    s.sendall(frame(0x0, 0x1, 1, P.frame(msg)))     # DATA, END_STREAM
    if ack_window:
        s.sendall(frame(0x8, 0, 0, struct.pack(">I", 1024)))  # WINDOW_UPDATE
    s.settimeout(12)
    buf = b""
    try:
        while len(buf) < 400:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    s.close()
    if not buf:
        print("%-40s (no response)" % tag)
        return
    ln = int.from_bytes(buf[0:3], "big")
    ftype, flags = buf[3], buf[4]
    sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
    payload = buf[9:9 + ln]
    status, g, msg_s = "?", "?", ""
    if ftype == 0x1:                       # HEADERS (HPACK decode, minimal)
        i = 0
        while i < len(payload):
            b = payload[i]
            if b & 0x80:                   # indexed
                idx = b & 0x7F
                if idx in STATIC:
                    if idx == 8:
                        pass
                i += 1
            elif b & 0x40:                 # literal incremental
                j = i + 1
                n = payload[j]
                j += 1
                name = payload[j:j + n].decode("latin1", "replace")
                j += n
                if j < len(payload):
                    n2 = payload[j]
                    j += 1
                    val = payload[j:j + n2].decode("latin1", "replace")
                    j += n2
                else:
                    val = ""
                if name == ":status":
                    status = val
                if name == "grpc-status":
                    g = val
                if name == "grpc-message":
                    msg_s = val
                i = j
            else:
                break
    elif ftype == 0x7:                    # GOAWAY
        status, g = "GOAWAY(%d)" % (int.from_bytes(payload[4:8], "big")
                                    if len(payload) >= 8 else -1), "-"
    elif ftype == 0x3:                    # RST_STREAM
        status = "RST_STREAM err=%d" % int.from_bytes(payload[0:4], "big")
    mark = "" if status == "502" else "   <<<<<< CHANGED"
    print("%-40s %s g=%s msg=%r%s" % (tag, status, g, msg_s[:60], mark))


UA = "grpc-c/1.0 (android; arm64; pesam)"

if __name__ == "__main__":
    go("literal-HPACK + WINDOW_UPDATE", "CMD_GET_SESSION_ID", UA)
    go("literal-HPACK, no SETTINGS", "CMD_GET_SESSION_ID", UA,
       with_settings=False)
    go("literal-HPACK CMD_GET_SERVER_ENV", "CMD_GET_SERVER_ENV", UA)
