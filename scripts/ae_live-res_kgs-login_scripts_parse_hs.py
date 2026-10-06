#!/usr/bin/env python3
"""Parse per-flow ClientHello/ServerHello from the 13:54 pcap (single segments)."""
import struct

PCAP = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
        r"\091ad105-36a7-44d4-88cd-8546a9d89b87\PCAPdroid_29_Sep_13_54_22.pcap")


def parse_exts(exts):
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
                                 struct.unpack(">%dH" % ((len(body) - 1) // 2,), body[1:])]
            except Exception:
                pass
    return out


def parse_ch(seg):
    assert seg[:1] == b"\x16"
    rlen = struct.unpack(">H", seg[3:5])[0]
    body = seg[5:5 + rlen]
    assert body[0] == 1
    hlen = int.from_bytes(body[1:4], "big")
    body = body[4:4 + hlen]
    ver = struct.unpack(">H", body[:2])[0]
    p = 2 + 32
    p += 1 + body[p]
    cs_len = struct.unpack(">H", body[p:p + 2])[0]
    ciphers = [hex(struct.unpack(">H", body[p + 2 + i:p + 4 + i])[0])
               for i in range(0, cs_len, 2)]
    p += 2 + cs_len
    p += 1 + body[p]
    exts = {}
    if p + 2 <= len(body):
        el = struct.unpack(">H", body[p:p + 2])[0]
        exts = parse_exts(body[p + 2:p + 2 + el])
    return ver, ciphers, exts


def parse_sh(seg):
    assert seg[:1] == b"\x16"
    rlen = struct.unpack(">H", seg[3:5])[0]
    body = seg[5:5 + rlen]
    assert body[0] == 2
    hlen = int.from_bytes(body[1:4], "big")
    body = body[4:4 + hlen]
    ver = struct.unpack(">H", body[:2])[0]
    p = 2 + 32 + 1 + body[2 + 32]
    cipher = hex(struct.unpack(">H", body[p:p + 2])[0])
    p += 2 + 1
    exts = {}
    if p + 2 <= len(body):
        el = struct.unpack(">H", body[p:p + 2])[0]
        exts = parse_exts(body[p + 2:p + 2 + el])
    return ver, cipher, exts


d = open(PCAP, "rb").read()
o = 24
flows = {}
while o + 16 <= len(d):
    ts_s, ts_u, incl, _ = struct.unpack("<IIII", d[o:o + 16])
    o += 16
    buf = d[o:o + incl]
    o += incl
    if buf[12:14] != b"\x08\x00" or buf[23] != 6:
        continue
    ihl = (buf[14] & 15) * 4
    src, dst = tuple(buf[26:30]), tuple(buf[30:34])
    sport, dport = struct.unpack(">HH", buf[14 + ihl:14 + ihl + 4])
    pay = buf[14 + ihl + (buf[14 + ihl + 12] >> 4) * 4:]
    if not pay or pay[:1] != b"\x16":
        continue
    tgt = (54, 203, 69, 122)
    if dst == tgt and dport == 443:
        flows.setdefault(("C", sport), []).append(pay)
    elif src == tgt and sport == 443:
        flows.setdefault(("S", dport), []).append(pay)

TGT = "54.203.69.122"
for (direction, port), segs in sorted(flows.items()):
    if direction == "C":
        for s in segs:
            if len(s) > 200 and s[5] == 1:
                ver, ciphers, exts = parse_ch(s)
                print("CH sport=%d ver=%s sni=%s alpn=%s supver=%s" % (
                    port, hex(ver), exts.get("sni"), exts.get("alpn"),
                    exts.get("supver")))
                print("   ciphers=%s" % ",".join(ciphers))
    else:
        for s in segs:
            if len(s) > 200 and s[5] == 2:
                ver, cipher, exts = parse_sh(s)
                print("SH sport=%d ver=%s cipher=%s alpn=%s" % (
                    port, hex(ver), cipher, exts.get("alpn")))
