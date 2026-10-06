#!/usr/bin/env python3
"""Dump every TLS ClientHello in the phone capture, grouped by flow.

The question this answers: the GAME reaches pes22-game.cs.konami.net and gets
served, while 50+ hand-built probes from this machine got 502/14. Same host,
same path, same body. If the front door were filtering on the handshake, the
game's ClientHello would have to be *unusual* in some specific way.

So: parse all of them out of the capture, exactly, and look.
"""
from __future__ import annotations

import glob
import hashlib
import os
import struct
import sys
from collections import OrderedDict

CAPS = sorted(glob.glob(r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
                        r"\uploads\*\*.pcap"))

NAME = {0: "server_name", 5: "status_request", 10: "supported_groups",
        11: "ec_point_formats", 13: "signature_algorithms",
        16: "application_layer_protocol_negotiation",
        17: "extended_master_secret", 18: "scts", 21: "padding",
        22: "encrypt_then_mac", 23: "session_ticket",
        27: "compress_certificate", 28: "record_size_limit",
        34: "delegated_credentials", 35: "session_ticket",
        41: "pre_shared_key", 42: "early_data", 43: "supported_versions",
        44: "cookie", 45: "psk_key_exchange_modes", 49: "post_handshake_auth",
        50: "signature_algorithms_cert", 51: "key_share",
        17513: "application_settings", 17613: "application_settings",
        65037: "encrypted_client_hello", 65281: "renegotiation_info",
        0xFF01: "renegotiation_info"}


def packets(path):
    """Yield (linktype, raw_frame) per packet.

    `tcpdump -i any` inside a Linux container writes Linux cooked capture
    (LINKTYPE_LINUX_SLL = 113), not Ethernet, so the link type has to be
    honoured rather than assumed. SLL2 (276) is handled too.
    """
    d = open(path, "rb").read()
    magic = d[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e, link = "<", struct.unpack("<I", d[20:24])[0]
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e, link = ">", struct.unpack(">I", d[20:24])[0]
    else:
        return
    o = 24
    while o + 16 <= len(d):
        _ts, _tu, incl, _orig = struct.unpack(e + "IIII", d[o:o + 16])
        o += 16
        if incl <= 0 or o + incl > len(d):
            break
        yield link, d[o:o + incl]
        o += incl


def ipv4_tcp(buf, link=1):
    """Return (src, dst, sport, dport, payload) for a TCP/IPv4 frame.

    Handles EN10MB (with optional 802.1Q), Linux SLL and SLL2.
    """
    if link == 1:                                   # EN10MB
        if len(buf) < 14:
            return None
        et = struct.unpack(">H", buf[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8):               # VLAN / QinQ
            if len(buf) < off + 4:
                return None
            et = struct.unpack(">H", buf[off + 2:off + 4])[0]
            off += 4
    elif link == 113:                               # LINUX_SLL
        if len(buf) < 16:
            return None
        et = struct.unpack(">H", buf[14:16])[0]
        off = 16
    elif link == 276:                               # LINUX_SLL2
        if len(buf) < 20:
            return None
        et = struct.unpack(">H", buf[0:2])[0]
        off = 20
    else:
        return None
    if et != 0x0800:
        return None

    if len(buf) < off + 20 or (buf[off] >> 4) != 4:
        return None
    ihl = (buf[off] & 15) * 4
    if buf[off + 9] != 6:                           # TCP only
        return None
    p = off + ihl
    if len(buf) < p + 20:
        return None
    sport, dport = struct.unpack(">HH", buf[p:p + 4])
    doff = (buf[p + 12] >> 4) * 4
    return (buf[off + 12:off + 16], buf[off + 16:off + 20],
            sport, dport, buf[p + doff:])


def parse_client_hello(rec):
    """rec = the raw TLS record (starting 0x16 0x03 ..). Returns a dict.

    ClientHello body layout (RFC 8446 s4.1.2):
        0        handshake_type = 1
        1..3     24-bit length           <-- easy to forget
        4..5     legacy_version
        6..37    random (32 bytes)
        38       legacy_session_id_len
    """
    if len(rec) < 6 or rec[0] != 0x16:
        return None
    hs_len = int.from_bytes(rec[3:5], "big")
    hs = rec[5:5 + hs_len]
    if len(hs) < 39 or hs[0] != 0x01:
        return None
    ver = struct.unpack(">H", hs[4:6])[0]
    p = 6 + 32                       # skip random
    sid_len = hs[p]
    p += 1 + sid_len
    if p + 2 > len(hs):
        return None
    cs_len = struct.unpack(">H", hs[p:p + 2])[0]
    ciphers = [struct.unpack(">H", hs[p + 2 + i:p + 4 + i])[0]
               for i in range(0, cs_len, 2)]
    p += 2 + cs_len
    if p >= len(hs):
        return {"ver": ver, "ciphers": ciphers, "exts": [], "legacy_only": True}
    cm_len = hs[p]
    p += 1 + cm_len
    exts = []
    if p + 2 <= len(hs):
        el = struct.unpack(">H", hs[p:p + 2])[0]
        b = hs[p + 2:p + 2 + el]
        o = 0
        while o + 4 <= len(b):
            et, e_len = struct.unpack(">HH", b[o:o + 4])
            exts.append((et, b[o + 4:o + 4 + e_len]))
            o += 4 + e_len
    return {"ver": ver, "ciphers": ciphers, "exts": exts, "legacy_only": False}


def ext_detail(et, body):
    try:
        if et == 0:
            n = struct.unpack(">H", body[3:5])[0]
            return body[5:5 + n].decode()
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
    if not CAPS:
        print("no pcaps found")
        return 1
    seen = OrderedDict()
    for cap in CAPS:
        for link, buf in packets(cap):
            t = ipv4_tcp(buf, link)
            if not t:
                continue
            src, dst, sport, dport, pay = t
            if dport != 443 or len(pay) < 200 or pay[0] != 0x16:
                continue
            info = parse_client_hello(pay)
            if not info:
                continue
            key = (hashlib.sha1(pay).hexdigest()[:10], len(pay))
            if key in seen:
                seen[key]["count"] += 1
                continue
            alpn = ""
            sni = ""
            for et, body in info["exts"]:
                d = ext_detail(et, body)
                if et == 0:
                    sni = d
                if et == 16:
                    alpn = d
            seen[key] = {
                "cap": os.path.basename(cap), "dst": ".".join(map(str, dst)),
                "sport": sport, "len": len(pay), "sni": sni, "alpn": alpn,
                "info": info, "count": 1,
                "bytes": pay,
            }

    print("=" * 78)
    print("EVERY ClientHello in the phone captures (phone is a real client)")
    print("=" * 78)
    game, other = [], []
    for k, v in seen.items():
        (game if "konami" in v["sni"] else other).append(v)

    for title, group in ((">>> KONAMI HOSTS (what the game actually did)", game),
                         ("--- every other host on the same connection set", other)):
        print("\n%s" % title)
        for v in sorted(group, key=lambda x: -x["len"]):
            i = v["info"]
            print("\n  sni=%s  alpn=[%s]" % (v["sni"], v["alpn"]))
            print("  dst=%s:%d  hello=%d B  ciphers=%d  exts=%d  x%d"
                  % (v["dst"], 443, v["len"], len(i["ciphers"]), len(i["exts"]),
                     v["count"]))
            print("  ciphers: %s" % " ".join(hex(c) for c in i["ciphers"]))
            order = " ".join(NAME.get(et, hex(et)) for et, _ in i["exts"])
            print("  ext order: %s" % order)
            if "pes22-game" in v["sni"]:
                for et, body in i["exts"]:
                    d = ext_detail(et, body)
                    if d and et in (0, 10, 13, 16, 21, 43, 51, 50):
                        print("      %-34s %s" % (NAME.get(et, hex(et)), d))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
