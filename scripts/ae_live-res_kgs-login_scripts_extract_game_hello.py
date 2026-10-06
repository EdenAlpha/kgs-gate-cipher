#!/usr/bin/env python3
"""Pull the game's real TLS ClientHello for the gRPC endpoint out of a match
export, and compare it with what our own TLS stack puts on the wire.

Why: the 502 comes from awselb/2.0 with content-length 0 -- the request body
is never processed -- while nginx on the same host is healthy. So the request
bytes cannot be the cause, and ALPN is eliminated. The remaining difference
visible from outside is the shape of the ClientHello itself.

passthrough_capture.csv holds complete IP packets as hex, both directions, with
event markers, so the game's own handshakes are recoverable from it byte for
byte. This finds every ClientHello, groups them by SNI and ALPN, and prints the
gRPC one in full.

That gives us the target to reproduce -- and, because the ClientHello is sent
in the clear, it is also directly replayable without completing a handshake, so
we can ask the load balancer whether a differently-shaped ClientHello changes
its behaviour.
"""
from __future__ import annotations

import binascii
import collections
import os
import re
import struct
import sys

NAME = {0: "server_name", 5: "status_request", 10: "supported_groups",
        11: "ec_point_formats", 13: "signature_algorithms",
        16: "application_layer_protocol_negotiation",
        17: "extended_master_secret", 18: "scts", 21: "padding",
        22: "encrypt_then_mac", 23: "session_ticket", 27: "compress_certificate",
        28: "record_size_limit", 34: "delegated_credentials",
        35: "session_ticket", 41: "pre_shared_key", 42: "early_data",
        43: "supported_versions", 44: "cookie",
        45: "psk_key_exchange_modes", 49: "post_handshake_auth",
        50: "signature_algorithms_cert", 51: "key_share",
        65037: "encrypted_client_hello", 65281: "renegotiation_info"}


def packets(csv_path):
    """Yield (ts_ms, dir, src, sport, dst, dport, ip_bytes) for each row."""
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.rstrip("\n").split(",")
            if len(parts) < 9:
                continue
            try:
                ts = int(parts[0])
                d, proto, src, sport, dst, dport = parts[1:7]
                raw = binascii.unhexlify(parts[8].strip())
            except Exception:
                continue
            yield ts, d, src, int(sport), dst, int(dport), raw


def tcp_segments(ip: bytes):
    """Return the TCP payload of an IPv4 packet, or None."""
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    p = ihl
    if len(ip) < p + 20:
        return None
    doff = (ip[p + 12] >> 4) * 4
    if doff < 20:
        return None
    return ip[p + doff:]


def parse_client_hello(rec: bytes):
    """Parse a TLS ClientHello record (or a reassembled run of records)."""
    out = []
    i = 0
    while i + 5 <= len(rec):
        if rec[i] != 0x16:
            break
        ln = int.from_bytes(rec[i + 3:i + 5], "big")
        body = rec[i + 5:i + 5 + ln]
        if len(body) < 39 or body[0] != 0x01:
            i += 5 + ln
            continue
        # type(1) len(3) legacy_version(2) random(32) sid_len(1)
        ver = struct.unpack(">H", body[4:6])[0]
        p = 38
        sid = body[p]
        p += 1 + sid
        csl = struct.unpack(">H", body[p:p + 2])[0]
        ciphers = [struct.unpack(">H", body[p + 2 + k:p + 4 + k])[0]
                   for k in range(0, csl, 2)]
        p += 2 + csl
        cml = body[p]
        p += 1 + cml
        exts = []
        if p + 2 <= len(body):
            el = struct.unpack(">H", body[p:p + 2])[0]
            b = body[p + 2:p + 2 + el]
            o = 0
            while o + 4 <= len(b):
                et, el2 = struct.unpack(">HH", b[o:o + 4])
                exts.append((et, b[o + 4:o + 4 + el2]))
                o += 4 + el2
        out.append({"ver": ver, "ciphers": ciphers, "exts": exts,
                    "raw": rec[i:i + 5 + ln]})
        i += 5 + ln
    return out


def detail(et, body):
    try:
        if et == 0:
            n = struct.unpack(">H", body[3:5])[0]
            return body[5:5 + n].decode("latin1")
        if et == 16:
            ps, p = [], 2
            while p < len(body):
                n = body[p]
                p += 1
                ps.append(body[p:p + n].decode("latin1"))
                p += n
            return ",".join(ps)
        if et in (10, 43, 13, 50):
            out, p = [], 1
            while p + 1 < len(body):
                out.append(hex(struct.unpack(">H", body[p:p + 2])[0]))
                p += 2
            return " ".join(out[:10])
        if et == 21:
            return "%d zero bytes" % len(body)
        if et == 51:
            return "%d B" % len(body)
    except Exception:
        pass
    return ""


def main() -> int:
    path = sys.argv[1]
    if not os.path.exists(path):
        print("not found:", path)
        return 1

    groups = collections.OrderedDict()
    total = hellos = 0
    for ts, d, src, sport, dst, dport, ip in packets(path):
        total += 1
        if dport != 443:
            continue
        pay = tcp_segments(ip)
        if not pay or len(pay) < 60 or pay[0] != 0x16:
            continue
        for info in parse_client_hello(pay):
            hellos += 1
            sni = alpn = ""
            for et, body in info["exts"]:
                if et == 0:
                    sni = detail(et, body)
                elif et == 16:
                    alpn = detail(et, body)
            key = (d, dst, sni, alpn, len(info["raw"]),
                   tuple(info["ciphers"]),
                   tuple(NAME.get(et, hex(et)) for et, _ in info["exts"]))
            g = groups.setdefault(key, {"n": 0, "info": info, "ts": ts,
                                        "src": src, "dst": dst, "dir": d})
            g["n"] += 1

    print("rows=%d  clientHellos=%d  distinct=%d\n"
          % (total, hellos, len(groups)))
    for key, g in groups.items():
        d, dst, sni, alpn, size, ciphers, extorder = key
        info = g["info"]
        vers = ""
        for et, body in info["exts"]:
            if et == 43:
                vers = detail(et, body)
        print("=" * 74)
        print("x%-3d  %s  %s:%d -> %s  SNI=%s  ALPN=[%s]"
              % (g["n"], g["dir"], g["src"], 0, g["dst"], sni, alpn))
        print("  record bytes    %d" % size)
        print("  legacy_version  0x%03x   supported_versions: %s"
              % (info["ver"], vers or "(none -> TLS 1.2 only)"))
        print("  ciphers (%d)     %s"
              % (len(ciphers), " ".join(hex(c) for c in ciphers)))
        print("  extensions (%d)  %s" % (len(extorder), " ".join(extorder)))
        for et, body in info["exts"]:
            dt = detail(et, body)
            if dt and et in (0, 10, 13, 16, 21, 43, 51, 50, 11):
                print("      %-34s %s" % (NAME.get(et, hex(et)), dt))
        h = info["raw"].hex()
        print("  hex:")
        for i in range(0, len(h), 64):
            print("    %s" % h[i:i + 64])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
