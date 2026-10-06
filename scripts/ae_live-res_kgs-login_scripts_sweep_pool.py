#!/usr/bin/env python3
"""Sweep EVERY address this game has ever been seen talking to.

Sources (all local, no new capture needed):
  * score_host.out  -- DNS scoring run on the user's own networks, lists the
                       IPs pes22-game.cs.konami.net resolved to for the real
                       app at the moment it was running
  * pcapdroid/*.pcap -- destination IPs of flows whose ClientHello carried
                       SNI pes22-game.cs.konami.net
  * today's DNS answers

For each address: TLS with SNI=pes22-game, POST the real script.  Anything
that is not "500" is interesting; a 200 is the endpoint that works.
"""
from __future__ import annotations

import glob
import os
import re
import socket
import ssl

HOST = "pes22-game.cs.konami.net"
PATH = "/pes22/gate/gate_CMD_LOGIN.php"
ENV = "/pes22/gate/gate_CMD_GET_SERVER_ENV.php"

BODY = (b"\x8a\xa5msgid\xa9CMD_LOGIN\xa4rqid\x00\xa7user_id\x00"
        b"\xaasession_id\xa0\xabmy_platform\xa0\xa9s_keyword\xa0"
        b"\xa4lang\xa3en\xa6region\xa0\xa8platform\xa0"
        b"\xaeclient_version\xa0")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
IPRE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def gather() -> dict:
    found = {}

    def add(ip, why):
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return
        a, b, c, d = (int(x) for x in ip.split("."))
        if max(a, b, c, d) > 255 or ip.startswith(("10.", "127.", "192.168.",
                                                   "172.")) or ip.startswith(
            "169.254"):
            return
        found.setdefault(ip, set()).add(why)

    for path in (os.path.join(ROOT, "score_host.out"),
                 os.path.join(HERE, "score_host.out")):
        if not os.path.exists(path):
            continue
        for line in open(path, "r", errors="replace"):
            if "->" in line:
                for ip in IPRE.findall(line.split("->")[-1]):
                    add(ip, "score_host")

    # pcap destinations of SNI-matching flows
    for pcap in glob.glob(os.path.join(HERE, "pcapdroid", "*.pcap")):
        try:
            data = open(pcap, "rb").read()
        except Exception:
            continue
        big = int.from_bytes(data[:4], "little") != 0xA1B2C3D4
        off = 24
        while off + 16 <= len(data):
            incl = int.from_bytes(data[off + 8:off + 12],
                                  "big" if big else "little")
            off += 16
            buf = data[off:off + incl]
            off += incl
            if len(buf) < 20 or (buf[0] >> 4) != 4:
                continue
            ihl = (buf[0] & 0xF) * 4
            if buf[9] != 6 or len(buf) < ihl + 20:
                continue
            payload = buf[ihl + 20:]
            if b"pes22-game.cs.konami.net" not in payload:
                continue
            add(socket.inet_ntoa(buf[16:20]), "pcap:" +
                os.path.basename(pcap)[:18])

    try:
        for ip in {i[4][0] for i in socket.getaddrinfo(
                HOST, 443, socket.AF_INET, socket.SOCK_STREAM)}:
            add(ip, "dns-today")
    except Exception:
        pass
    return found


def probe(ip, path, body):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=8),
                         server_hostname=HOST) as s:
        s.settimeout(10)
        req = ("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: "
               "application/x-www-form-urlencoded\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n" % (path, HOST, len(body))).encode()
        s.sendall(req + body)
        d = b""
        while len(d) < 3000:
            b = s.recv(1500)
            if not b:
                break
            d += b
    return d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"


def main() -> int:
    pool = gather()
    print("pool of %d addresses" % len(pool), flush=True)
    for ip in sorted(pool):
        print("   %-16s %s" % (ip, ",".join(sorted(pool[ip]))), flush=True)
    print(flush=True)

    interesting = []
    for ip in sorted(pool):
        try:
            line = probe(ip, PATH, BODY)
        except Exception as e:
            line = "ERR %s" % type(e).__name__
        mark = "" if "500" in line else "   <<<<<< NOT 500"
        print("  %-16s %-34s %s" % (ip, line, mark), flush=True)
        if "500" not in line and not line.startswith("ERR"):
            interesting.append((ip, line))
    print("\n=== non-500 answers ===", flush=True)
    for ip, line in interesting:
        try:
            print("  %-16s ENV  %s" % (ip, probe(ip, ENV, BODY)), flush=True)
        except Exception as e:
            print("  %-16s ENV  ERR %s" % (ip, type(e).__name__), flush=True)
        print("  %-16s LOGIN %s" % (ip, line), flush=True)
    if not interesting:
        print("  (none -- every reachable address returns 500)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
