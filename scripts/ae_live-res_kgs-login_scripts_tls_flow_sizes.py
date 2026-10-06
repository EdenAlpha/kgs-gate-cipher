#!/usr/bin/env python3
"""Did the app's OWN session to pes22-game.cs.konami.net work?

TLS hides the bytes, not the shape.  A request that gets an answer shows a
client record followed by a server record; a request the server rejects shows
client records with nothing back.

Prints, in capture order: direction, TLS record type, length.

  type 20 = change_cipher_spec   21 = alert/close_notify
  type 22 = handshake             23 = application data
"""
from __future__ import annotations

import glob
import os
import socket
from collections import defaultdict

import dpkt

PDIR = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
        r"\peerlink_work\pcapdroid")
SNI = b"pes22-game.cs.konami.net"
TYPE = {20: "CCS", 21: "ALERT", 22: "HS", 23: "APP"}


def records(buf):
    i = 0
    while i + 5 <= len(buf):
        typ, ver = buf[i], buf[i + 1]
        if typ not in (0x14, 0x15, 0x16, 0x17) or ver != 0x03:
            break
        ln = (buf[i + 3] << 8) | buf[i + 4]
        yield typ, ln
        i += 5 + ln


def main() -> int:
    for pcap in sorted(glob.glob(os.path.join(PDIR, "*.pcap"))):
        data = open(pcap, "rb").read()
        big = int.from_bytes(data[:4], "little") != 0xA1B2C3D4
        off = 24
        events = defaultdict(list)      # (client, sport, server, dport)
        clients = {}
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
            t = ip.data
            pl = bytes(t.data or b"")
            if not pl:
                continue
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            port = (t.sport, t.dport)
            if SNI in pl:
                clients[(src, t.sport, dst, t.dport)] = True
            for typ, ln in records(pl):
                if typ not in TYPE:
                    continue
                for key in list(clients):
                    if {key[0], key[2]} == {src, dst} and \
                       {key[1], key[3]} == {t.sport, t.dport}:
                        who = "C" if src == key[0] else "S"
                        events[key].append("%s%s:%d" % (who, TYPE[typ], ln))
                        break
        print("=" * 70)
        print(os.path.basename(pcap))
        for key, ev in events.items():
            print("  %s:%d -> %s:%d" % key)
            line = " ".join(ev)
            print("    " + line[:1600])
            n_c = sum(1 for e in ev if e.startswith("C"))
            n_s = sum(1 for e in ev if e.startswith("S"))
            print("    C=%d records  S=%d records  %s"
                  % (n_c, n_s, "server answered" if n_s > 2 else "NO ANSWER"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
