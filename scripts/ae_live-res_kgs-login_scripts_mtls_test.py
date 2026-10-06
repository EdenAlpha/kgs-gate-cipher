#!/usr/bin/env python3
"""Extract the client identity the app ships, and test the gate with it.

Facts taken straight out of libUE4.so:
  0xba1e86  4096-bit RSA private key
  0xb0a2d2  certificate  CN=localhost, OU=2 Prod, O=KDE, L=Chuo-ku, ST=Tokyo
            -- its public key matches that private key exactly
  0x9d9bc5  CA root       CN=CA root,   OU=2 Prod, O=KDE, ... (the pin)
"""
from __future__ import annotations

import base64
import hashlib
import re
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.serialization import load_der_private_key

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
HOST = "pes22-game.cs.konami.net"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
FORM = "application/x-www-form-urlencoded"
BODY = open("getserverenv_body.bin", "rb").read()

data = open(SO, "rb").read()


def pem(der: bytes, label: bytes) -> bytes:
    b = base64.b64encode(der)
    lines = [b[i:i + 64] for i in range(0, len(b), 64)]
    return (b"-----BEGIN " + label + b"-----\n" + b"\n".join(lines)
            + b"\n-----END " + label + b"-----\n")


def all_pem(label: bytes):
    out = []
    for m in re.finditer(b"-----BEGIN " + re.escape(label) + b"-----", data):
        st = m.start()
        term = b"-----END " + label + b"-----"
        e = data.find(term, st)
        if e < 0:
            continue
        e += len(term)
        mid = data[st:e].split(b"-----BEGIN " + label)[1].split(term)[0]
        b64 = bytes(c for c in mid if c not in b"\r\n \t")
        try:
            out.append((st, base64.b64decode(b64)))
        except Exception:
            pass
    return out


def spki(pub) -> bytes:
    return pub.public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)


certs = [(st, d) for st, d in all_pem(b"CERTIFICATE") if len(d) > 50]
keys = all_pem(b"RSA PRIVATE KEY")
key_der = max(keys, key=lambda x: len(x[1]))[1]
key = load_der_private_key(key_der, password=None)
kh = hashlib.sha256(spki(key.public_key())).hexdigest()
print("private key: %d bits" % key.public_key().public_numbers().n.bit_length())

client_der = ca_der = None
for st, der in certs:
    c = x509.load_der_x509_certificate(der)
    h = hashlib.sha256(spki(c.public_key())).hexdigest()
    tag = "MATCHES KEY" if h == kh else ""
    print("  %08x  %-58s %s" % (st, c.subject.rfc4514_string(), tag))
    if h == kh:
        client_der = der
    elif "CA" in c.subject.rfc4514_string():
        ca_der = der

if client_der is None:
    raise SystemExit("no certificate matches the private key")

open("client_key.pem", "wb").write(pem(key_der, b"RSA PRIVATE KEY"))
open("client_cert.pem", "wb").write(pem(client_der, b"CERTIFICATE"))
if ca_der:
    open("ca_root.pem", "wb").write(pem(ca_der, b"CERTIFICATE"))
print("wrote client_key.pem, client_cert.pem, ca_root.pem\n")


def attempt(path, body, ct, use_cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])       # keep the wire format readable
    if use_cert:
        ctx.load_cert_chain("client_cert.pem", "client_key.pem")
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
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
    s.close()
    if not d:
        return "EMPTY RESPONSE", b""
    return d.split(b"\r\n", 1)[0].decode("latin1"), \
        d.partition(b"\r\n\r\n")[2][:300]


CASES = [("raw msgpack", FORM, BODY),
         ("req=<hex>", FORM, b"req=" + BODY.hex().encode()),
         ("x-msgpack", "application/x-msgpack", BODY)]

for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
    path = "/pes22/gate/gate_%s.php" % msgid
    print("===", path)
    for use_cert in (False, True):
        tag = "WITH cert" if use_cert else "no cert   "
        for label, ct, b in CASES:
            try:
                line, body = attempt(path, b, ct, use_cert)
            except Exception as e:
                print("  %s %-12s ERR %s: %s" % (tag, label,
                                                  type(e).__name__, e))
                continue
            flag = "   <<<<<< DIFFERENT!" if "500" not in line else ""
            print("  %s %-12s %-32s %r%s" % (tag, label, line, body, flag))
    print()
