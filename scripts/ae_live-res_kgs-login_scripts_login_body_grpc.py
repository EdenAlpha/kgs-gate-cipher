#!/usr/bin/env python3
"""Send the app's REAL 582-byte CMD_LOGIN body over the gRPC CommandStream.

Gap in every earlier gRPC test: they all carried the 129-byte
CMD_GET_SERVER_ENV envelope.  The app's actual login message is 582 bytes
with 29 fields (produced by the game's own writer 0x76b1b28 and saved to
login_body.bin).  Never once sent over the stream.

Also test packMode=JSON (the schema has both) -- we never tried a JSON body
over gRPC.
"""
from __future__ import annotations

import json
import socket
import ssl
import struct

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
ALPN = ["grpc-exp", "h2"]


# ---------------- MessagePack reader (handles map16/array16 too) --------
def mp_read(raw, i=0):
    b = raw[i]
    i += 1
    if b <= 0x7F:
        return b, i
    if 0x80 <= b <= 0x8F:
        n = b & 0x0F
    elif b == 0xDE:
        n = int.from_bytes(raw[i:i + 2], "big")
        i += 2
    elif b == 0xDF:
        n = int.from_bytes(raw[i:i + 4], "big")
        i += 4
    elif 0x90 <= b <= 0x9F or b == 0xDC or b == 0xDD:
        if 0x90 <= b <= 0x9F:
            n = b & 0x0F
        elif b == 0xDC:
            n = int.from_bytes(raw[i:i + 2], "big")
            i += 2
        else:
            n = int.from_bytes(raw[i:i + 4], "big")
            i += 4
        out = []
        for _ in range(n):
            v, i = mp_read(raw, i)
            out.append(v)
        return out, i
    elif 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        return raw[i:i + n].decode("utf-8", "replace"), i + n
    elif b == 0xD9:
        n = raw[i]; i += 1
        return raw[i:i + n].decode("utf-8", "replace"), i + n
    elif b == 0xDA:
        n = int.from_bytes(raw[i:i + 2], "big"); i += 2
        return raw[i:i + n].decode("utf-8", "replace"), i + n
    elif b == 0xC4:
        n = raw[i]; i += 1
        return raw[i:i + n], i + n
    elif b == 0xC5:
        n = int.from_bytes(raw[i:i + 2], "big"); i += 2
        return raw[i:i + n], i + n
    elif b == 0xC6:
        n = int.from_bytes(raw[i:i + 4], "big"); i += 4
        return raw[i:i + n], i + n
    elif b == 0xD2:
        return int.from_bytes(raw[i:i + 4], "big", signed=True), i + 4
    elif b == 0xCE:
        return int.from_bytes(raw[i:i + 4], "big"), i + 4
    elif b == 0xCD:
        return int.from_bytes(raw[i:i + 2], "big"), i + 2
    elif b == 0xCC:
        return raw[i], i + 1
    elif b == 0xC0:
        return None, i
    elif b == 0xC2:
        return False, i
    elif b == 0xC3:
        return True, i
    else:
        return f"<tag 0x{b:02x}>", i
    d = {}
    for _ in range(n):
        k, i = mp_read(raw, i)
        v, i = mp_read(raw, i)
        d[k] = v
    return d, i


def to_json(o):
    if isinstance(o, dict):
        return {str(k): to_json(v) for k, v in o.items()}
    if isinstance(o, list):
        return [to_json(v) for v in o]
    return o


# ---------------- proto / gRPC framing ---------------------------------
def varint(v):
    o = bytearray()
    while True:
        x = v & 0x7F
        v >>= 7
        o.append(x | 0x80 if v else x)
        if not v:
            return bytes(o)


def fstr(f, s):
    raw = s if isinstance(s, (bytes, bytearray)) else s.encode()
    return bytes([f << 3 | 2]) + varint(len(raw)) + raw


def fvarint(f, v):
    return bytes([f << 3 | 0]) + varint(v)


def request(msgid, body, path, pack):
    return (fstr(1, msgid) + fvarint(2, pack) + fstr(3, body)
            + fstr(4, path))


def frame(p):
    return b"\x00" + struct.pack(">I", len(p)) + p


def call(msgid, body, path, pack):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(ALPN)
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    cfg = h2.config.H2Configuration(client_side=True,
                                    header_encoding="utf-8")
    c = h2.connection.H2Connection(config=cfg)
    c.initiate_connection()
    s.sendall(c.data_to_send())
    c.send_headers(1, [(":method", "POST"), (":scheme", "https"),
                       (":authority", HOST), (":path", METHOD),
                       ("content-type", "application/grpc"),
                       ("te", "trailers"), ("user-agent", "grpc-c/1.0"),
                       ("grpc-encoding", "identity"),
                       ("grpc-accept-encoding", "identity")],
                   end_stream=False)
    c.send_data(1, frame(request(msgid, body, path, pack)), end_stream=True)
    s.sendall(c.data_to_send())

    s.settimeout(15)
    hdrs, trail, out = {}, {}, b""
    try:
        while True:
            d = s.recv(65535)
            if not d:
                break
            for ev in c.receive_data(d):
                if isinstance(ev, h2.events.ResponseReceived):
                    hdrs = dict(ev.headers)
                elif isinstance(ev, h2.events.DataReceived):
                    out += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    trail = dict(ev.headers)
            o = c.data_to_send()
            if o:
                s.sendall(o)
            if hdrs or trail:
                break
    except socket.timeout:
        hdrs[":status"] = "(timeout)"
    except Exception as e:
        hdrs[":status"] = f"ERR-{type(e).__name__}"
    s.close()
    st = hdrs.get(":status")
    g = trail.get("grpc-status") or hdrs.get("grpc-status")
    m = (trail.get("grpc-message") or hdrs.get("grpc-message") or "")[:140]
    return st, g, m, out


def main() -> int:
    raw = open("login_body.bin", "rb").read()
    decoded, _ = mp_read(raw, 0)
    print(f"=== login_body.bin: {len(raw)} bytes, "
          f"{len(decoded) if isinstance(decoded, dict) else '?'} fields ===",
          flush=True)
    print(json.dumps(to_json(decoded), indent=2, default=str)[:1400],
          flush=True)

    env_raw = open("real_body.bin", "rb").read()
    env_dec, _ = mp_read(env_raw, 0)

    cases = [
        ("CMD_LOGIN / MSGPACK / 582B", "CMD_LOGIN", raw,
         "gate/gate_CMD_LOGIN.php", 1),
        ("CMD_LOGIN / MSGPACK / 582B + json-ish", "CMD_LOGIN", raw,
         "CmdLogin.php", 1),
        ("CMD_LOGIN / JSON / 582B-as-json", "CMD_LOGIN",
         json.dumps(to_json(decoded), separators=(",", ":")).encode(),
         "gate/gate_CMD_LOGIN.php", 0),
        ("CMD_LOGIN / JSON / compact", "CMD_LOGIN",
         json.dumps(to_json(decoded), separators=(",", ":")).encode(),
         "gate/gate_CMD_LOGIN.php", 1),
        ("CMD_LOGIN / MSGPACK / 582B  path=CmdLogin.php", "CMD_LOGIN", raw,
         "CmdLogin.php", 1),
        ("CMD_GET_SERVER_ENV / MSGPACK / 129B",
         "CMD_GET_SERVER_ENV", env_raw,
         "gate/gate_CMD_GET_SERVER_ENV.php", 1),
        ("CMD_GET_SERVER_ENV / JSON / 129B-as-json",
         "CMD_GET_SERVER_ENV",
         json.dumps(to_json(env_dec), separators=(",", ":")).encode(),
         "gate/gate_CMD_GET_SERVER_ENV.php", 0),
        ("CMD_GET_KGS_GUEST_LOGIN_TOKEN / MSGPACK / 582B",
         "CMD_GET_KGS_GUEST_LOGIN_TOKEN", raw,
         "gate/gate_CMD_GET_KGS_GUEST_LOGIN_TOKEN.php", 1),
    ]

    print("\n=== over the gRPC CommandStream ===", flush=True)
    results = {}
    for label, msgid, body, path, pack in cases:
        try:
            st, g, m, out = call(msgid, body, path, pack)
        except Exception as e:
            print(f"  {label:52s} ERR {type(e).__name__}: {e}", flush=True)
            continue
        tag = "   <<<<<< CHANGED!" if (st != "502" or g != "14") else ""
        print(f"  {label:52s} {st}/{g}  {m}{tag}", flush=True)
        if out:
            print(f"      body {len(out)}B {out[:200]!r}", flush=True)
            try:
                v, _ = mp_read(out, 0)
                print(f"      decoded: "
                      f"{json.dumps(to_json(v), default=str)[:400]}",
                      flush=True)
            except Exception:
                pass
        results[label] = {"status": st, "grpc": g, "msg": m,
                          "body_hex": out.hex()}
    open("login_body_try.json", "w").write(json.dumps(results, indent=2))
    print("\n-> login_body_try.json", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
