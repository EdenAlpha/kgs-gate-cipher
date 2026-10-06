#!/usr/bin/env python3
"""Fire the login the instant we have an auth code.

    python fire_login.py <auth_code> [--session-id ...]

Steps (the game's own request shapes):
  1. CMD_GET_KGS_GUEST_LOGIN_TOKEN   -> guest token
  2. CMD_LOGIN                       -> session_id / user_id
  3. CMD_CREATEJOIN_ROOM             -> the room code

The body layout is the one the game's own writer (0x76b1b28) produced: a
25-field MessagePack map with the field order it used.  Only `auth_code`,
`hash`, `client_version`, `platform` differ from the ctor's placeholders --
and those come from the web login + the device.
"""
from __future__ import annotations

import json
import socket
import ssl
import struct
import sys

HOST = "pes22-game.cs.konami.net"
FORM = "application/x-www-form-urlencoded"

# identity values taken from the app's own plaintext diagnostics (## NTLInfo /
# ## AppInfo in the PcapDroid captures) -- not guesses
TITLE = "PES2022"
LOCALE = "US"
UID = "3c5aad3c6b8425c611ebe2f5da6c25af"   # real uid, from the user's 2026-09-28 capture
OPT = "22011111"
LIBVER = "1.17.1-Android-15"
APPVER = "6.0.1"           # the value the working app sends as client_version
PLATFORM = "PES"


def mp_str(s):
    b = s.encode() if isinstance(s, str) else bytes(s)
    return (bytes([0xA0 | len(b)]) + b) if len(b) < 32 else \
        (b"\xd9" + bytes([len(b)]) + b)


def mp_int(v):
    return bytes([v]) if 0 <= v < 128 else \
        b"\xd2" + int(v).to_bytes(4, "big", signed=True)


def build_body(msgid, auth_code, hsh, session_id="", extra=None):
    """Field order exactly as the game's writer 0x76b1b28 emits."""
    fields = [
        ("msgid", msgid),
        ("rqid", 1),
        ("user_id", 0),
        ("session_id", session_id),
        ("my_platform", UID),
        ("s_keyword", ""),
        ("auth_code", auth_code),
        ("hash", hsh),
        ("client_version", APPVER),
        ("platform", PLATFORM),
        ("device", [("device_identifier", UID)]),
        ("lang", LOCALE),
        ("country_code", []),
        ("region", LOCALE),
        ("pcspec", ""),
        ("cross_platform_option", ""),
        ("is_disable_sharing", 0),
        ("os_version", "15"),
        ("model_name", "Pixel 7"),
        ("gpu_name", "Adreno"),
        ("soc_name", "Tensor"),
        ("is_rooting", 0),
        ("phy_mem_used_mib", 2048),
        ("phy_mem_available_mib", 4096),
        ("app_storage_used_mib", 1024),
        ("app_storage_available_mib", 8192),
        ("data_storage_used_mib", 512),
        ("data_storage_available_mib", 8192),
        ("payment_store_link_send_info", 0),
        ("country_code", []),
    ]
    if extra:
        fields = fields[:-1] + list(extra) + [fields[-1]]
    out = bytes([0x80 | len(fields)])
    for k, v in fields:
        out += mp_str(k)
        if isinstance(v, int):
            out += mp_int(v)
        elif isinstance(v, list):
            out += bytes([0x90 | len(v)])      # array (country_code = [])
        elif isinstance(v, dict):
            out += bytes([0x80 | len(v)])
            for k2, v2 in v.items():
                out += mp_str(k2) + mp_str(v2)
        else:
            out += mp_str(v)
    return out


def post(path, payload, ct=FORM):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=30),
                        server_hostname=HOST)
    L = [f"POST {path} HTTP/1.1", f"Host: {HOST}", "User-Agent: PESAM",
         "Accept: */*", "Connection: close"]
    if ct:
        L.append("Content-Type: " + ct)
    L.append(f"Content-Length: {len(payload)}")
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + payload)
    s.settimeout(30)
    d = b""
    while len(d) < 262144:
        b = s.recv(8192)
        if not b:
            break
        d += b
    s.close()
    line = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    body = d.partition(b"\r\n\r\n")[2]
    return line, body


def decode(raw: bytes):
    """Minimal MessagePack reader."""
    def rd(i):
        b = raw[i]
        i += 1
        return b, i

    def rdval(i):
        b, i = rd(i)
        if b <= 0x7F:
            return b, i
        if 0xA0 <= b <= 0xBF:
            n = b & 0x1F
            return raw[i:i + n].decode("utf-8", "replace"), i + n
        if b == 0xD9:
            n = raw[i]
            i += 1
            return raw[i:i + n].decode("utf-8", "replace"), i + n
        if b == 0xD2:
            return int.from_bytes(raw[i:i + 4], "big", signed=True), i + 4
        if b == 0xCC:
            return raw[i], i + 1
        if b == 0xCD:
            return int.from_bytes(raw[i:i + 2], "big"), i + 2
        if b == 0xCE:
            return int.from_bytes(raw[i:i + 4], "big"), i + 4
        if b == 0xC0:
            return None, i
        if b == 0xC2:
            return False, i
        if b == 0xC3:
            return True, i
        if 0x90 <= b <= 0x9F:
            n = b & 0x0F
            out = []
            for _ in range(n):
                v, i = rdval(i)
                out.append(v)
            return out, i
        if 0x80 <= b <= 0x8F:
            n = b & 0x0F
            d = {}
            for _ in range(n):
                k, i = rdval(i)
                v, i = rdval(i)
                d[k] = v
            return d, i
        return f"<tag 0x{b:02x}>", i

    v, _ = rdval(0)
    return v


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python fire_login.py <auth_code> [hash]")
        return 2
    auth_code = sys.argv[1]
    hsh = sys.argv[2] if len(sys.argv) > 2 else ""
    session_id = sys.argv[3] if len(sys.argv) > 3 else ""

    print(f"auth_code = {auth_code[:12]}... ({len(auth_code)} chars)",
          flush=True)
    print(f"hash      = {hsh or '(empty)'}", flush=True)

    steps = [
        ("CMD_GET_KGS_GUEST_LOGIN_TOKEN",
         "/pes22/gate/gate_CMD_GET_KGS_GUEST_LOGIN_TOKEN.php"),
        ("CMD_LOGIN", "/pes22/gate/gate_CMD_LOGIN.php"),
    ]
    results = {}
    for msgid, path in steps:
        payload = build_body(msgid, auth_code, hsh, session_id)
        print(f"\n=== {msgid}  ({len(payload)}B) ===", flush=True)
        try:
            line, body = post(path, payload)
        except Exception as e:
            print(f"   ERR {type(e).__name__}: {e}", flush=True)
            continue
        print(f"   {line}", flush=True)
        print(f"   body: {body[:400]!r}", flush=True)
        # try msgpack
        try:
            parsed = decode(body)
            print(f"   decoded: {json.dumps(parsed, default=str)[:500]}",
                  flush=True)
            results[msgid] = parsed
        except Exception as e:
            print(f"   (not msgpack: {e})", flush=True)

    # if login worked, try to create a room
    if "CMD_LOGIN" in results:
        lid = results["CMD_LOGIN"]
        sid = lid.get("session_id") or session_id
        uid = lid.get("user_id", 0)
        print(f"\n=== CMD_CREATEJOIN_ROOM (session={sid}) ===", flush=True)
        payload = build_body("CMD_CREATEJOIN_ROOM", auth_code, hsh, sid)
        try:
            line, body = post("/pes22/gate/gate_CMD_CREATEJOIN_ROOM.php",
                              payload)
            print(f"   {line}", flush=True)
            print(f"   body: {body[:600]!r}", flush=True)
            print(f"   decoded: "
                  f"{json.dumps(decode(body), default=str)[:800]}", flush=True)
        except Exception as e:
            print(f"   ERR {type(e).__name__}: {e}", flush=True)

    open("login_results.json", "w").write(
        json.dumps(results, indent=2, default=str))
    print("\n-> login_results.json", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
