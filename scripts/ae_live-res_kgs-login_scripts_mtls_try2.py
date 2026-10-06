#!/usr/bin/env python3
"""Does the gate accept the client certificate the app ships?

Binary facts (all from libUE4.so, nothing invented):
  * 4096-bit RSA private key at 0xba1e86
  * certificate at 0xb0a2d2  CN=localhost, OU=2 Prod, O=KDE, L=Chuo-ku,
    ST=Tokyo, C=jp   -- public key matches that private key exactly
  * CA root at 0x9d9bc5       CN=CA root, OU=2 Prod, O=KDE, ... (the pin)
"""
from __future__ import annotations

import base64
import socket
import ssl
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
HOST = "pes22-game.cs.konami.net"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
FORM = "application/x-www-form-urlencoded"
BODY = open("getserverenv_body.bin", "rb").read()
data = open(SO, "rb").read()


# client_key.pem / client_cert.pem / ca_root.pem are produced by
# extract_certs.py, which parses the stored blobs reliably.
import os
for f in ("client_key.pem", "client_cert.pem", "ca_root.pem"):
    if not os.path.exists(f):
        raise SystemExit("missing %s -- run extract_certs.py first" % f)
print("using client_key.pem / client_cert.pem / ca_root.pem\n")


def attempt(path, body, ct, use_cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    if use_cert:
        ctx.load_cert_chain("client_cert.pem", "client_key.pem")
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    peer = s.getpeercert(binary_form=False)
    L = ["POST %s HTTP/1.1" % path, "Host: " + HOST, "User-Agent: " + UA,
         "Accept: */*", "Connection: close"]
    if ct:
        L.append("Content-Type: " + ct)
    L.append("Content-Length: %d" % len(body))
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    s.settimeout(25)
    d = b""
    while len(d) < 65536:
        b = s.recv(8192)
        if not b:
            break
        d += b
    alpn = s.selected_alpn_protocol()
    s.close()
    if not d:
        return "EMPTY RESPONSE (alpn=%s)" % alpn, b""
    st = d.split(b"\r\n", 1)[0].decode("latin1")
    return st + "  alpn=" + str(alpn), d.partition(b"\r\n\r\n")[2][:300]


CASES = [
    ("raw msgpack", FORM, BODY),
    ("req=<hex>", FORM, b"req=" + BODY.hex().encode()),
    ("x-msgpack", "application/x-msgpack", BODY),
]

for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
    path = "/pes22/gate/gate_%s.php" % msgid
    print("===", path)
    for use_cert in (False, True):
        tag = "WITH cert" if use_cert else "no cert   "
        for label, ct, b in CASES:
            try:
                line, body = attempt(path, b, ct, use_cert)
            except Exception as e:
                print("  %s %-12s TLS/ERR %s: %s" % (tag, label,
                                                     type(e).__name__, e))
                continue
            good = " 500" not in line
            flag = "   <<<<<< DIFFERENT!" if good else ""
            print("  %s %-12s %s  %r%s" % (tag, label, line, body, flag))
    print()
