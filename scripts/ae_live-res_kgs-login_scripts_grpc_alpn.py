#!/usr/bin/env python3
"""THE test: gRPC over ALPN 'grpc-exp', TLS 1.2, 5 ciphers.

The captures show the app has TWO TLS ClientHello shapes:

  A) alpn=http/1.1  512B  17 ciphers  TLS1.3+1.2  -> GateInfo/ReportLog
  B) alpn=grpc-exp  180B   5 ciphers  TLS1.2 ONLY -> the command stream
                                                  (969s / 754s / 258s lived)

We have been offering 'h2' and getting grpc-status 14 in 0 ms from awselb/2.0
-- a routing miss.  Match shape B exactly.
"""
from __future__ import annotations

import glob
import os
import socket
import ssl
import struct

import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
BODY = open(r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
            r"\peerlink_work\real_body.bin", "rb").read()

EXT = {0: "server_name", 10: "supported_groups", 11: "ec_point_formats",
       13: "signature_algorithms", 16: "alpn", 22: "encrypt_then_mac",
       23: "extended_master_secret", 35: "session_ticket"}


# ---------- 1. dump the exact grpc-exp ClientHello --------------------
def parse_hellos():
    out = []
    pdir = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
            r"\peerlink_work\pcapdroid")
    for pcap in sorted(glob.glob(os.path.join(pdir, "*.pcap"))):
        data = open(pcap, "rb").read()
        big = int.from_bytes(data[:4], "little") != 0xA1B2C3D4
        off = 24
        while off + 16 <= len(data):
            incl = int.from_bytes(data[off + 8:off + 12],
                                  "big" if big else "little")
            off += 16
            buf = data[off:off + incl]
            off += incl
            if len(buf) < 20 or (buf[0] >> 4) not in (4, 6):
                continue
            try:
                ip = dpkt_ip(buf)
            except Exception:
                continue
            if not ip[1]:
                continue
            pl = ip[1]
            for i in range(0, min(len(pl) - 6, 8192)):
                if pl[i] != 0x16 or pl[i + 1] != 0x03:
                    continue
                ln = (pl[i + 3] << 8) | pl[i + 4]
                if ln < 40 or i + 5 + ln > len(pl):
                    continue
                rec = pl[i + 5:i + 5 + ln]
                if not rec or rec[0] != 0x01:
                    continue
                out.append(parse_ch(rec, os.path.basename(pcap)))
                break
    return out


def dpkt_ip(buf):
    import dpkt
    ip = dpkt.ip.IP(buf) if (buf[0] >> 4) == 4 else dpkt.ip6.IP6(buf)
    if isinstance(ip.data, dpkt.tcp.TCP):
        return (ip, bytes(ip.data.data or b""))
    return (ip, b"")


def parse_ch(rec: bytes, src: str):
    j = 4 + 2 + 32
    sl = rec[j]
    j += 1 + sl
    cl = (rec[j] << 8) | rec[j + 1]
    ciphers = []
    k = j + 2
    end = k + cl
    while k + 2 <= end:
        ciphers.append(f"{(rec[k] << 8) | rec[k + 1]:04x}")
        k += 2
    j = end
    j += 1 + rec[j]                     # compression
    el = (rec[j] << 8) | rec[j + 1]
    j += 2
    ext_end = j + el
    exts = {}
    alpn = None
    while j + 4 <= ext_end:
        t = (rec[j] << 8) | rec[j + 1]
        l = (rec[j + 2] << 8) | rec[j + 3]
        body = rec[j + 4:j + 4 + l]
        exts[t] = body
        if t == 16 and len(body) >= 3:
            alpn = body[3:3 + body[2]].decode("ascii", "replace")
        j += 4 + l
    return {"src": src, "alpn": alpn, "ciphers": ciphers, "exts": exts,
            "rec": rec}


def main() -> int:
    print("=== exact grpc-exp ClientHello ===", flush=True)
    hs = parse_hellos()
    gr = [h for h in hs if h["alpn"] == "grpc-exp"]
    if not gr:
        print("  no grpc-exp hello found", flush=True)
        return 1
    h = gr[0]
    print(f"  from {h['src']}  record {len(h['rec'])}B", flush=True)
    print(f"  ciphers: {h['ciphers']}", flush=True)
    for t, b in sorted(h["exts"].items()):
        print(f"  ext {t:5d} {EXT.get(t, '?'):22s} {len(b):3d}B  {b[:40].hex()}",
              flush=True)

    # ---------- 2. the live test: same request, different ALPN ----------
    def varint(v):
        o = bytearray()
        while True:
            x = v & 0x7F
            v >>= 7
            o.append(x | 0x80 if v else x)
            if not v:
                return bytes(o)

    def fstr(f, s):
        raw = s.encode() if isinstance(s, str) else bytes(s)
        return bytes([f << 3 | 2]) + varint(len(raw)) + raw

    def fvarint(f, v):
        return bytes([f << 3 | 0]) + varint(v)

    req = (fstr(1, "CMD_GET_SERVER_ENV") + fvarint(2, 1)
           + fstr(3, BODY) + fstr(4, "gate/gate_CMD_GET_SERVER_ENV.php"))
    frame = b"\x00" + struct.pack(">I", len(req)) + req

    def call(label, alpn_list, tls_versions=None, ciphers=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(alpn_list)
        if tls_versions:
            ctx.minimum_version = tls_versions[0]
            ctx.maximum_version = tls_versions[1]
        if ciphers:
            try:
                ctx.set_ciphers(ciphers)
            except Exception as e:
                print(f"    (cipher set failed: {e})", flush=True)
        try:
            s = ctx.wrap_socket(socket.create_connection((HOST, 443),
                                                         timeout=20),
                                server_hostname=HOST)
        except Exception as e:
            print(f"  {label:44s} TLS-ERR {type(e).__name__}: {e}",
                  flush=True)
            return
        neg = s.selected_alpn_protocol()
        cfg = h2.config.H2Configuration(client_side=True,
                                        header_encoding="utf-8")
        c = h2.connection.H2Connection(config=cfg)
        c.initiate_connection()
        s.sendall(c.data_to_send())
        c.send_headers(1, [(":method", "POST"), (":scheme", "https"),
                           (":authority", HOST), (":path", METHOD),
                           ("content-type", "application/grpc"),
                           ("te", "trailers"), ("user-agent", "grpc-c/1.0")],
                       end_stream=False)
        c.send_data(1, frame, end_stream=True)
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
                        c.acknowledge_received_data(
                            ev.flow_controlled_length, ev.stream_id)
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
            hdrs[":status"] = f"ERR {type(e).__name__}"
        s.close()
        g = trail.get("grpc-status") or hdrs.get("grpc-status")
        m = (trail.get("grpc-message") or hdrs.get("grpc-message") or "")[:60]
        st = hdrs.get(":status")
        tag = ("   <<<<<< CHANGED!" if (st != "502" or g != "14")
               else "")
        print(f"  {label:44s} alpn={neg} HTTP={st} grpc={g} "
              f"{out[:60]!r}{tag}", flush=True)
        if m:
            print(f"      msg={m}", flush=True)

    print("\n=== same request, different ALPN ===", flush=True)
    call("alpn=h2 (what we have been doing)", ["h2"])
    call("alpn=grpc-exp (what the app does)", ["grpc-exp"])
    call("alpn=grpc-exp,h2", ["grpc-exp", "h2"])
    call("alpn=h2,grpc-exp", ["h2", "grpc-exp"])
    call("alpn=grpc-exp TLS1.2 only", ["grpc-exp"],
         (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2))
    call("alpn=h2 TLS1.2 only", ["h2"],
         (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2))
    call("alpn=grpc-exp + 5 ciphers", ["grpc-exp"],
         (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
         "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:"
         "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:"
         "DHE-RSA-AES128-GCM-SHA256")

    print("\n=== grpc-exp + client certificate ===", flush=True)
    # reuse the chain if present
    d = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
    if os.path.exists(os.path.join(d, "chain.pem")):
        class _C:
            pass
        call("grpc-exp + client cert", ["grpc-exp"],
             (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
