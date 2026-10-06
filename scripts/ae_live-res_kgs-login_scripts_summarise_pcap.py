#!/usr/bin/env python3
"""Summarise a pcap: list every TLS ClientHello, fully parsed.

Used on the capture taken inside the redroid container, where `tcpdump -i any`
writes Linux cooked capture (LINKTYPE_LINUX_SLL 113) rather than Ethernet, so
the link type is read from the file header instead of assumed.

Prints, for each ClientHello: size, offered ciphers, the extension order, ALPN,
SNI, and the TLS versions offered. That last group is the point -- it is what
has to be compared against what our own TLS stack emits.
"""
from __future__ import annotations

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


def open_pcap(path):
    d = open(path, "rb").read()
    m = d[:4]
    if m in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e, link = "<", struct.unpack("<I", d[20:24])[0]
    elif m in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e, link = ">", struct.unpack(">I", d[20:24])[0]
    else:
        raise SystemExit("unknown pcap magic %s" % m.hex())
    return d, e, link


def iter_frames(d, e, link):
    o = 24
    while o + 16 <= len(d):
        incl, = struct.unpack(e + "I", d[o + 8:o + 12])
        o += 16
        if incl <= 0 or o + incl > len(d):
            break
        yield d[o:o + incl]
        o += incl


def l3_offset(buf, link):
    if link == 1:
        if len(buf) < 14:
            return None
        et = struct.unpack(">H", buf[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8):
            if len(buf) < off + 4:
                return None
            et = struct.unpack(">H", buf[off + 2:off + 4])[0]
            off += 4
        return off if et == 0x0800 else None
    if link == 113:
        if len(buf) < 16 or struct.unpack(">H", buf[14:16])[0] != 0x0800:
            return None
        return 16
    if link == 276:
        if len(buf) < 20 or struct.unpack(">H", buf[0:2])[0] != 0x0800:
            return None
        return 20
    return None


def tcp_payload(buf, link):
    off = l3_offset(buf, link)
    if off is None or len(buf) < off + 20:
        return None
    if buf[off] >> 4 != 4 or buf[off + 9] != 6:
        return None
    ihl = (buf[off] & 15) * 4
    p = off + ihl
    if len(buf) < p + 20:
        return None
    sport, dport = struct.unpack(">HH", buf[p:p + 4])
    doff = (buf[p + 12] >> 4) * 4
    return sport, dport, buf[p + doff:]


def parse_ch(rec):
    """Parse a TLS ClientHello record."""
    if len(rec) < 6 or rec[0] != 0x16:
        return None
    hs = rec[5:5 + int.from_bytes(rec[3:5], "big")]
    # 0: type(1) 1..3: 24-bit length 4..5: legacy_version 6..37: random
    if len(hs) < 39 or hs[0] != 0x01:
        return None
    ver = struct.unpack(">H", hs[4:6])[0]
    p = 38
    sid = hs[p]
    p += 1 + sid
    if p + 2 > len(hs):
        return None
    csl = struct.unpack(">H", hs[p:p + 2])[0]
    ciphers = [struct.unpack(">H", hs[p + 2 + i:p + 4 + i])[0]
               for i in range(0, csl, 2)]
    p += 2 + csl
    if p >= len(hs):
        return {"ver": ver, "ciphers": ciphers, "exts": []}
    cml = hs[p]
    p += 1 + cml
    exts = []
    if p + 2 <= len(hs):
        el = struct.unpack(">H", hs[p:p + 2])[0]
        b = hs[p + 2:p + 2 + el]
        o = 0
        while o + 4 <= len(b):
            et, el2 = struct.unpack(">HH", b[o:o + 4])
            exts.append((et, b[o + 4:o + 4 + el2]))
            o += 4 + el2
    return {"ver": ver, "ciphers": ciphers, "exts": exts}


def detail(et, body):
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
            return " ".join(out[:8])
        if et == 21:
            return "%d zero bytes" % len(body)
        if et == 51:
            return "%d B" % len(body)
    except Exception:
        pass
    return ""


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: summarise_pcap.py <file.pcap>")
        return 1
    d, e, link = open_pcap(sys.argv[1])
    print("pcap: %d bytes  linktype=%d (1=EN10MB 113=LinuxSLL 276=SLL2)"
          % (len(d), link))
    n = ch = 0
    for buf in iter_frames(d, e, link):
        n += 1
        t = tcp_payload(buf, link)
        if not t:
            continue
        sport, dport, pay = t
        if dport != 443 or len(pay) < 60 or pay[0] != 0x16:
            continue
        info = parse_ch(pay)
        if not info:
            continue
        ch += 1
        sni = alpn = ""
        for et, body in info["exts"]:
            if et == 0:
                sni = detail(et, body)
            elif et == 16:
                alpn = detail(et, body)
        vers = ""
        for et, body in info["exts"]:
            if et == 43:
                vers = detail(et, body)
        print("\n=== ClientHello #%d  %d bytes  (record %d) ==="
              % (ch, len(pay), int.from_bytes(pay[3:5], "big") + 4))
        print("  legacy_version   0x%03x" % info["ver"])
        print("  supported_versions %s" % (vers or "(not offered -> TLS 1.2 max)"))
        print("  sni              %s" % sni)
        print("  alpn             [%s]" % alpn)
        print("  ciphers (%d)      %s"
              % (len(info["ciphers"]), " ".join(hex(c) for c in info["ciphers"])))
        print("  extensions (%d)   %s"
              % (len(info["exts"]),
                 " ".join(NAME.get(et, hex(et)) for et, _ in info["exts"])))
        print("  full hex (first 400 B):")
        h = pay[:400].hex()
        for i in range(0, len(h), 64):
            print("    %s" % h[i:i + 64])
    print("\ntotal packets=%d  clientHellos=%d" % (n, ch))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
