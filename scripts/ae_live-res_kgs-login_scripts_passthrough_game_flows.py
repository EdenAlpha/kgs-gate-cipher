#!/usr/bin/env python3
"""Pull the game's Konami TLS flows out of a passthrough_capture.csv and
decode the plaintext parts of the handshake (SNI, ALPN, versions, ciphers).

This is internet-side ground truth: exactly the bytes Konami received.
"""
from __future__ import annotations

import csv
import struct
import sys
from collections import defaultdict

PATH = sys.argv[1] if len(sys.argv) > 1 else (
    r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\match_new2"
    r"\passthrough_capture.csv")


def parse_exts(exts: bytes) -> dict:
    out = {}
    o = 0
    while o + 4 <= len(exts):
        et, el = struct.unpack(">HH", exts[o:o + 4])
        body = exts[o + 4:o + 4 + el]
        o += 4 + el
        if et == 0:
            try:
                out["sni"] = body[5:5 + struct.unpack(">H", body[3:5])[0]].decode()
            except Exception:
                pass
        elif et == 16:
            protos, p = [], 2
            while p < len(body):
                n = body[p]
                p += 1
                protos.append(body[p:p + n].decode("latin1"))
                p += n
            out["alpn"] = protos
        elif et == 43:
            try:
                out["supver"] = [hex(v) for v in
                                 struct.unpack(">%dH" % ((len(body) - 1) // 2,),
                                               body[1:])]
            except Exception:
                pass
    return out


def parse_ch(seg: bytes):
    body = seg[5:]
    if len(body) < 4:
        raise ValueError("short record")
    hlen = int.from_bytes(body[1:4], "big")
    hs = body[4:4 + hlen]
    if len(hs) < 2 + 32 + 2:
        raise ValueError("short hello")
    p = 2 + 32
    p += 1 + hs[p]
    csl = struct.unpack(">H", hs[p:p + 2])[0]
    ciphers = [hex(struct.unpack(">H", hs[p + 2 + i:p + 4 + i])[0])
               for i in range(0, csl, 2)]
    p += 2 + csl
    p += 1 + hs[p]
    exts = {}
    if p + 2 <= len(hs):
        el = struct.unpack(">H", hs[p:p + 2])[0]
        exts = parse_exts(hs[p + 2:p + 2 + el])
    return hex(struct.unpack(">H", hs[:2])[0]), ciphers, exts


def parse_sh(seg: bytes):
    body = seg[5:]
    if len(body) < 4:
        raise ValueError("short record")
    hlen = int.from_bytes(body[1:4], "big")
    hs = body[4:4 + hlen]
    if len(hs) < 2 + 32 + 2:
        raise ValueError("short hello")
    p = 2 + 32
    p += 1 + hs[p]
    cipher = hex(struct.unpack(">H", hs[p:p + 2])[0])
    p += 3
    exts = {}
    if p + 2 <= len(hs):
        el = struct.unpack(">H", hs[p:p + 2])[0]
        exts = parse_exts(hs[p + 2:p + 2 + el])
    return hex(struct.unpack(">H", hs[:2])[0]), cipher, exts


def main() -> int:
    packets = []
    with open(PATH, encoding="utf-8", errors="replace") as f:
        for r in csv.reader(f):
            if len(r) < 9 or r[0].startswith("#") or r[0] == "ts_ms":
                continue
            try:
                ts, direction, proto, src, sport, dst, dport, iplen, hexp = (
                    int(r[0]), r[1], r[2], r[3], int(r[4]), r[5], int(r[6]),
                    int(r[7]), r[8])
                raw = bytes.fromhex(hexp)
            except ValueError:
                continue
            packets.append((ts, direction, proto, src, sport, dst, dport,
                            iplen, raw))

    # find every packet whose payload mentions a konami name (SNI is clear)
    konami_pkts = []
    sni_ips = defaultdict(set)
    for p in packets:
        _, _, proto, src, sport, dst, dport, _, raw = p
        body = raw[40:]
        if b"konami.net" in body or b"konami.com" in body:
            konami_pkts.append(p)
            for name in (b"pes22-game.cs.konami.net",
                         b"ntljp.service.konami.net",
                         b"ntl.service.konami.net",
                         b"info.service.konami.net",
                         b"pesam.stun.service.konami.net"):
                if name in body:
                    sni_ips[name.decode()].add(
                        (src, sport, dst, dport) if dport == 443
                        else (dst, dport, src, sport))

    print("packets parsed: %d" % len(packets))
    print("konami-mentioning packets: %d" % len(konami_pkts))
    for name, s in sni_ips.items():
        print("  %-32s seen in %d flow(s)" % (name, len(s)))

    # Rebuild the game flows: all packets of the 443 connections that had SNI
    game_flows = set()
    for name, s in sni_ips.items():
        for f in s:
            if f[3] == 443 or f[1] == 443:
                game_flows.add(f)

    print("\n=== GAME FLOWS (%d) ===" % len(game_flows))
    for (a, ap, b, bp) in sorted(game_flows, key=lambda x: (x[2], x[1])):
        ups = [p for p in packets
               if p[2] == "tcp" and p[3] == a and p[4] == ap
               and p[5] == b and p[6] == bp and p[8][40:]]
        downs = [p for p in packets
                 if p[2] == "tcp" and p[3] == b and p[4] == bp
                 and p[5] == a and p[6] == ap and p[8][40:]]
        up = sum(len(p[8]) - 40 for p in ups)
        down = sum(len(p[8]) - 40 for p in downs)
        if not ups and not downs:
            continue
        print("\n%s:%d -> %s:%d   up %d pkts/%dB   down %d pkts/%dB"
              % (a, ap, b, bp, len(ups), up, len(downs), down))
        for p in sorted(ups, key=lambda x: x[0]):
            body = p[8][40:]
            if body[:1] == b"\x16" and len(body) > 100:
                try:
                    ver, ciphers, exts = parse_ch(body)
                except Exception:
                    continue
                print("   CH ver=%s sni=%s alpn=%s supver=%s"
                      % (ver, exts.get("sni"), exts.get("alpn"),
                         exts.get("supver")))
                print("      ciphers=%s" % ",".join(ciphers[:20]))
        for p in sorted(downs, key=lambda x: x[0]):
            body = p[8][40:]
            if body[:1] == b"\x16" and len(body) > 100:
                try:
                    ver, cipher, exts = parse_sh(body)
                except Exception:
                    continue
                print("   SH ver=%s cipher=%s alpn=%s"
                      % (ver, cipher, exts.get("alpn")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
