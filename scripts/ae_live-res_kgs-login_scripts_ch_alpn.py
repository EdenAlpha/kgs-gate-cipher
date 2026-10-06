#!/usr/bin/env python3
"""Which TLS protocol does the real app advertise in its ClientHello?

If the game only offers ALPN h2, every HTTP/1.1 request we hand-make is being
answered by a different code path than the app uses.

Parses the first ClientHello to pes22-game.cs.konami.net out of each capture
and prints version, ALPN list, cipher suites and SNI.
"""
from __future__ import annotations

import glob
import os
import socket
import struct

import dpkt

PDIR = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
        r"\peerlink_work\pcapdroid")
SNI = b"pes22-game.cs.konami.net"


def parse_chello(ribs: bytes):
    """ribs = TLS record payload (handshake messages concatenated)."""
    out = {}
    i = 0
    while i + 4 <= len(ribs):
        htype = ribs[i]
        ln = int.from_bytes(ribs[i + 1:i + 4], "big")
        body = ribs[i + 4:i + 4 + ln]
        if htype != 1 or len(body) < 34 + 2:
            i += 4 + ln
            continue
        p = 34
        sid_len = body[p]
        p += 1 + sid_len
        if p + 2 > len(body):
            break
        cs_len = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        ciphers = [body[j:j + 2].hex() for j in range(p, p + cs_len, 2)]
        p += cs_len
        comp_len = body[p]
        p += 1 + comp_len
        if p + 2 > len(body):
            out["ciphers"] = ciphers
            break
        ext_total = struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        end = min(p + ext_total, len(body))
        alpn, sni, versions = [], None, []
        while p + 4 <= end:
            etype, elen = struct.unpack(">HH", body[p:p + 4])
            ed = body[p + 4:p + 4 + elen]
            p += 4 + elen
            if etype == 16 and len(ed) >= 2:            # ALPN
                q = 2
                while q < len(ed):
                    n = ed[q]
                    alpn.append(ed[q + 1:q + 1 + n].decode("latin1"))
                    q += 1 + n
            elif etype == 0 and len(ed) > 5:            # SNI
                sni = ed[5:5 + struct.unpack(">H", ed[3:5])[0]].decode()
            elif etype == 43:                           # supported versions
                n = ed[0]
                versions = [ed[j:j + 2].hex() for j in range(1, 1 + n, 2)]
        out.update(alpn=alpn, sni=sni, versions=versions, ciphers=ciphers)
        i += 4 + ln
    return out


def main() -> int:
    for pcap in sorted(glob.glob(os.path.join(PDIR, "*.pcap"))):
        data = open(pcap, "rb").read()
        big = int.from_bytes(data[:4], "little") != 0xA1B2C3D4
        off = 24
        seen = False
        while off + 16 <= len(data):
            incl = int.from_bytes(data[off + 8:off + 12],
                                  "big" if big else "little")
            off += 16
            buf = data[off:off + incl]
            off += incl
            if len(buf) < 20 or (buf[0] >> 4) != 4:
                continue
            try:
                ip = dpkt.ip.IP(buf)
            except Exception:
                continue
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            pl = bytes(ip.data.data or b"")
            if SNI not in pl or len(pl) < 9 or pl[0] != 0x16:
                continue
            ln = struct.unpack(">H", pl[3:5])[0]
            res = parse_chello(pl[5:5 + ln])
            if not res:
                continue
            print("%-34s" % os.path.basename(pcap))
            print("    sni       = %s" % res.get("sni"))
            print("    ALPN      = %s" % res.get("alpn"))
            print("    versions  = %s" % res.get("versions"))
            print("    n_ciphers = %d  first=%s" % (
                len(res.get("ciphers") or []),
                ",".join((res.get("ciphers") or [])[:8])))
            seen = True
            break
        if not seen:
            print("%-34s (no ClientHello to the game host)" %
                  os.path.basename(pcap))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
