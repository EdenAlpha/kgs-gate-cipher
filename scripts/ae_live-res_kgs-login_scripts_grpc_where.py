#!/usr/bin/env python3
"""Is grpc-status:14 from the app or from a proxy in between?

Evidence to collect:
  1. is grpc-status in the response HEADERS or the TRAILERS?  (a real gRPC
     server puts it in trailers; Envoy/ALB immediate-failures put it in
     headers)
  2. how long until the response?  (sub-5ms = local middleware, 50ms+ =
     an upstream round trip)
  3. is it deterministic over 8 identical requests?
  4. does the connection survive (GOAWAY / RST_STREAM)?
"""
from __future__ import annotations

import socket
import ssl
import struct
import time

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
UA = "grpc-c/1.0 (android; arm64; pesam)"
BODY = open("real_body.bin", "rb").read()


def varint(v):
    o = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        o.append(b | 0x80 if v else b)
        if not v:
            return bytes(o)


def fstr(f, s):
    raw = s.encode("utf-8") if isinstance(s, str) else bytes(s)
    return bytes([f << 3 | 2]) + varint(len(raw)) + raw


def request(msgid, body, path, pack=1):
    return (fstr(1, msgid) + bytes([2 << 3 | 0]) + varint(pack)
            + fstr(3, body) + fstr(4, path))


def frame(p):
    return b"\x00" + struct.pack(">I", len(p)) + p


def call(payload, label=""):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    t_conn = time.time()
    sock = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=20),
                           server_hostname=HOST)
    t_conn = time.time() - t_conn
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    c = h2.connection.H2Connection(config=cfg)
    c.initiate_connection()
    sock.sendall(c.data_to_send())
    c.send_headers(1, [(":method", "POST"), (":scheme", "https"),
                       (":authority", HOST), (":path", METHOD),
                       ("content-type", "application/grpc"),
                       ("te", "trailers"), ("user-agent", UA)],
                   end_stream=False)
    t0 = time.time()
    c.send_data(1, frame(payload), end_stream=True)
    sock.sendall(c.data_to_send())

    sock.settimeout(12)
    hdrs, trail = {}, {}
    out = b""
    events = []
    t_first = None
    try:
        while True:
            d = sock.recv(65535)
            if not d:
                events.append("CONN-CLOSED")
                break
            for ev in c.receive_data(d):
                if t_first is None:
                    t_first = time.time() - t0
                name = type(ev).__name__
                events.append(name)
                if isinstance(ev, h2.events.ResponseReceived):
                    hdrs = {k: v for k, v in ev.headers}
                elif isinstance(ev, h2.events.DataReceived):
                    out += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length,
                                                ev.stream_id)
                elif isinstance(ev, h2.events.TrailersReceived):
                    trail = {k: v for k, v in ev.headers}
                elif isinstance(ev, h2.events.StreamReset):
                    events.append(f"RESET={ev.error_code}")
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    events.append(f"GOAWAY={ev.error_code}")
                elif isinstance(ev, h2.events.StreamEnded):
                    pass
            o = c.data_to_send()
            if o:
                sock.sendall(o)
            if hdrs or trail:
                if not c.streams or 1 not in c.streams:
                    break
                if c.streams.get(1) and c.streams[1].closed:
                    break
    except socket.timeout:
        events.append("TIMEOUT")
    except Exception as e:
        events.append(f"ERR {type(e).__name__}")
    sock.close()

    hs = hdrs.get("grpc-status")
    ts = trail.get("grpc-status")
    hm = hdrs.get("grpc-message")
    tm = trail.get("grpc-message")
    return {
        "conn_ms": round(t_conn * 1000, 1),
        "first_ms": round((t_first or 0) * 1000, 1),
        "http": hdrs.get(":status"),
        "hdr_grpc": hs,
        "trl_grpc": ts,
        "hdr_msg": hm,
        "trl_msg": tm,
        "server": hdrs.get("server"),
        "body": len(out),
        "events": events,
    }


def show(label, r):
    loc = ("HEADERS" if r["hdr_grpc"] is not None else
           "TRAILERS" if r["trl_grpc"] is not None else "-")
    g = r["hdr_grpc"] or r["trl_grpc"]
    m = r["hdr_msg"] or r["trl_msg"]
    print(f"  {label:34s} conn={r['conn_ms']:6.1f}ms first={r['first_ms']:6.1f}ms "
          f"HTTP={r['http']} grpc={g} @{loc} msg={m}", flush=True)
    return g


print("=== where does grpc-status live? how fast? ===", flush=True)
payload = request("CMD_GET_SERVER_ENV", BODY,
                  "gate/gate_CMD_GET_SERVER_ENV.php")
r = call(payload, "valid req")
show("valid CommandRequest", r)
print(f"     server={r['server']}  events={r['events']}", flush=True)

r2 = call(b"\x00", "garbage")
show("garbage 1-byte", r2)
print(f"     server={r2['server']}  events={r2['events']}", flush=True)

print("\n=== determinism: 8 identical valid requests ===", flush=True)
seen = {}
for i in range(8):
    g = show(f"run {i+1}", call(payload))
    seen[g] = seen.get(g, 0) + 1
print(f"  tally: {seen}", flush=True)

print("\n=== timing distribution (5 runs) ===", flush=True)
for i in range(5):
    r = call(payload)
    print(f"  run {i+1}: first response at {r['first_ms']}ms "
          f"(conn {r['conn_ms']}ms)  grpc="
          f"{r['hdr_grpc'] or r['trl_grpc']}", flush=True)
