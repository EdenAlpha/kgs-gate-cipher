#!/usr/bin/env python3
"""Stream sequence test: does the server want CMD_CONNECT_GRPC first?

Keeps ONE bidi stream open (like the game): msg1 = CMD_CONNECT_GRPC,
msg2 = CMD_GET_SERVER_ENV, then reads whatever comes back.
"""
import socket
import ssl
import struct
import sys

import msgpack

import h2.config
import h2.connection
import h2.events

sys.path.insert(0, r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work")
import probe_game_ip as P  # noqa: E402

HOST = "pes22-game.cs.konami.net"
IP = "54.203.69.122"
UA = "grpc-c/1.0 (android; arm64; pesam)"


def env(msgid):
    d = {"msgid": msgid, "rqid": 0,
         "user_id": "3c5aad3c6b8425c611ebe2f5da6c25af",
         "session_id": "", "my_platform": "Android", "s_keyword": "",
         "lang": "US", "region": "US", "platform": "Android",
         "client_version": "6.0.1"}
    return msgpack.packb(d, use_bin_type=True)


def open_conn():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["grpc-exp", "h2"])
    s = ctx.wrap_socket(socket.create_connection((IP, 443), timeout=20),
                        server_hostname=HOST)
    c = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding="utf-8"))
    c.initiate_connection()
    c.send_headers(1, [(":method", "POST"), (":scheme", "https"),
                       (":authority", HOST),
                       (":path", "/command_service.CommandService/CommandStream"),
                       ("content-type", "application/grpc"),
                       ("te", "trailers"),
                       ("user-agent", UA),
                       ("grpc-encoding", "identity"),
                       ("grpc-accept-encoding", "identity")],
                   end_stream=False)
    s.sendall(c.data_to_send())
    return s, c


def read_all(s, c, seconds=12, want_end=True):
    s.settimeout(seconds)
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
                elif isinstance(ev, h2.events.StreamEnded):
                    if want_end:
                        s.sendall(c.data_to_send())
                        return hdrs, trail, out
            o = c.data_to_send()
            if o:
                s.sendall(o)
    except socket.timeout:
        pass
    return hdrs, trail, out


def show(tag, hdrs, trail, out):
    st = hdrs.get(":status")
    g = trail.get("grpc-status", hdrs.get("grpc-status", "-"))
    m = (trail.get("grpc-message", hdrs.get("grpc-message", "")) or "")[:120]
    print(f"{tag}: status={st} g={g} msg={m!r} data={len(out)}B {out[:150]!r}",
          flush=True)


def main():
    variants = [
        ("CONNECT/''", "CmdConnectGrpc", "", "CmdConnectGrpc", ""),
        ("CONNECT/php", "CmdConnectGrpc", "CmdConnectGrpc.php",
         "CmdConnectGrpc", "CmdConnectGrpc.php"),
        ("CONNECT/gate-php", "CmdConnectGrpc", "gate/gate_CMD_CONNECT_GRPC.php",
         "CmdGetServerEnv", "gate/gate_CMD_GET_SERVER_ENV.php"),
    ]
    for tag, m1, p1, m2, p2 in variants:
        try:
            s, c = open_conn()
            r1 = P.request(m1, env(m1), p1, 1)
            c.send_data(1, P.frame(r1), end_stream=False)
            s.sendall(c.data_to_send())
            h, t, o = read_all(s, c, seconds=4, want_end=False)
            show(f"{tag} after-msg1", h, t, o)
            if h.get(":status") == "502":
                s.close()
                continue
            r2 = P.request(m2, env(m2), p2, 1)
            c.send_data(1, P.frame(r2), end_stream=True)
            s.sendall(c.data_to_send())
            h, t, o = read_all(s, c, seconds=12)
            show(f"{tag} after-msg2", h, t, o)
            s.close()
        except Exception as e:
            print(f"{tag}: EXC {type(e).__name__}: {e}", flush=True)


if __name__ == "__main__":
    main()
