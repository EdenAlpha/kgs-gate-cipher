#!/usr/bin/env python3
"""A gate client written from scratch.

  body = IV(16) || AES-256-CBC(KEY_B, PKCS7( zlib( msgpack(msg) ) ))
  sign = b64( HMAC_SHA256(secret|str(rand^clock), body) || clock_le || rand_le )
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import random
import socket
import ssl
import struct
import zlib

import msgpack
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_B = bytes.fromhex(
    "43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")
SIGN_SECRET = b"Xrq-RtAF_91MAE82"

HOST = "pes22-game.cs.konami.net"
UA = "PES/1.0 (ANDROID 14; 0; redroid14_arm64_only; 0; 6.0.1; ; 11.0.1; )"


# --------------------------------------------------- s_keyword (SOLVED)
# s_keyword is not stored anywhere -- it is computed at request time:
#
#     s_keyword[i] = CONST[i] ^ client_version[i % len(client_version)]
#
# CONST is baked into every build as an obfuscated .data.rel.ro struct,
# decoded by the single-string decoder (out[i] = p[i]^T1[i%9]^T2[i%12]^0x75)
# and cached in a global.  Because CONST changes per app build, any
# s_keyword copied from an older capture silently stops working on update.
SK_CONST = {
    "11.0.1": b"hGcKSg6k",     # struct @0x9823c38 in 11.0.1 libUE4.so
    "11.1.0": b"YE5PUd6m",     # struct @0x9932ab0 in 11.1.0 libUE4.so
}
SK_BUILD = "11.1.0"
CLIENT_VERSION = "6.1.0"


def s_keyword(client_version: str = CLIENT_VERSION,
              build: str = SK_BUILD) -> str:
    const = SK_CONST[build]
    cv = client_version.encode()
    return bytes(const[i] ^ cv[i % len(cv)]
                 for i in range(len(const))).decode("latin-1")


def ua(client_version: str = CLIENT_VERSION, os_name: str = "ANDROID 14",
       user: str = "0", model: str = "redroid14_arm64_only",
       app_version: str = "11.1.0", t: int | None = None) -> str:
    import time
    return ("PES/1.0 (%s; %s; %s; %d; %s; ; %s; )"
            % (os_name, user, model, int(time.time()) if t is None else t,
               client_version, app_version))


def envelope(msgid: str, rqid: int, client_version: str = CLIENT_VERSION,
             user_id: int = 0, session_id: str = "", platform: str = "ANDROID",
             my_platform: str | None = None, lang: str = "US",
             region: str = "REGION_US", build: str = SK_BUILD,
             **extra) -> dict:
    """Build a full 10-key gate envelope with a correctly derived s_keyword."""
    msg = {
        "msgid": msgid,
        "rqid": rqid,
        "user_id": user_id,
        "session_id": session_id,
        "my_platform": my_platform or platform,
        "s_keyword": s_keyword(client_version, build),
        "lang": lang,
        "region": region,
        "platform": platform,
        "client_version": client_version,
    }
    msg.update(extra)
    return msg


# ---------------------------------------------------------------- encode
def encode(msg) -> bytes:
    packed = msgpack.packb(msg, use_bin_type=True)
    raw = zlib.compress(packed, 9)
    iv = get_random_bytes(16)
    pad = 16 - (len(raw) % 16)
    raw = raw + bytes([pad]) * pad
    return iv + AES.new(KEY_B, AES.MODE_CBC, iv).encrypt(raw)


def decode(body: bytes) -> dict:
    iv, ct = body[:16], body[16:]
    raw = AES.new(KEY_B, AES.MODE_CBC, iv).decrypt(ct)
    raw = raw[: -raw[-1]]
    if raw[:2] == b"\x1f\x8b":          # gzip -- responses
        import gzip
        raw = gzip.decompress(raw)
    else:
        raw = zlib.decompress(raw)
    return msgpack.unpackb(raw, raw=False, strict_map_key=False)


# ------------------------------------------------------------------ sign
def make_sign(body: bytes, clock: int | None = None,
              rand_: int | None = None) -> str:
    if clock is None:
        clock = random.getrandbits(32)
    if rand_ is None:
        rand_ = random.getrandbits(32)
    mixed = (rand_ ^ clock) & 0xFFFFFFFF
    key = SIGN_SECRET + b"|" + str(mixed).encode()
    mac = hmac.new(key, body, hashlib.sha256).digest()
    return base64.b64encode(mac + struct.pack("<II", clock, rand_)).decode()


def verify_sign(body: bytes, sign: str) -> bool:
    raw = base64.b64decode(sign)
    if len(raw) != 40:
        return False
    clock, rand_ = struct.unpack("<II", raw[32:40])
    key = SIGN_SECRET + b"|" + str((rand_ ^ clock) & 0xFFFFFFFF).encode()
    return hmac.compare_digest(hmac.new(key, body, hashlib.sha256).digest(),
                               raw[:32])


# ------------------------------------------------------------------ send
def headers_for(body: bytes, sign: str) -> list[tuple[str, str]]:
    return [
        ("Accept-Language", "jp"),
        ("User-Agent", UA),
        ("pes-custom-encrypt", "AES256"),
        ("Accept-Encoding", "gzip"),
        ("Content-Encoding", "gzip"),
        ("Cookie", "sign=%s;" % sign),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Host", HOST),
        ("Connection", "close"),
    ]


def post(cmd: str, body: bytes, sign: str, timeout: int = 25):
    """POST one gate request.  Returns (status_line, headers, raw_body)."""
    path = "/pes22/gate/gate_%s.php" % cmd
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=timeout)
    conn.request("POST", path, body=body, headers=dict(headers_for(body, sign)))
    resp = conn.getresponse()
    data = resp.read()
    out = (resp.reason, dict(resp.getheaders()), data)
    conn.close()
    return out


def send_msg(cmd: str, msg: dict, timeout: int = 25):
    body = encode(msg)
    sign = make_sign(body)
    status, hdrs, data = post(cmd, body, sign, timeout)
    return status, hdrs, data


if __name__ == "__main__":
    # offline self-test: encode -> decode roundtrip, and sign roundtrip
    probe = {"msgid": "CMD_GET_SERVER_ENV", "rqid": 0, "lang": "en"}
    b = encode(probe)
    assert decode(b) == probe, decode(b)
    s = make_sign(b)
    assert verify_sign(b, s)
    print("offline roundtrip OK  body=%d bytes  sign=%s" % (len(b), s))

    # s_keyword derivation must reproduce the captured 11.0.1 value exactly
    assert s_keyword("6.0.1", "11.0.1") == "^iSebQ\x18[", \
        repr(s_keyword("6.0.1", "11.0.1"))
    print("s_keyword regression OK  6.0.1/11.0.1 -> %r"
          % s_keyword("6.0.1", "11.0.1"))
    print("s_keyword 11.1.0/6.1.0 -> %r" % s_keyword("6.1.0", "11.1.0"))
    print("s_keyword 11.1.0/6.1.1 -> %r" % s_keyword("6.1.1", "11.1.0"))
