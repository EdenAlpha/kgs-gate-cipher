#!/usr/bin/env python3
"""Try the gate with the client certificate the app ships.

The binary contains a 4096-bit RSA private key and a matching certificate
    CN=localhost, OU=2 Prod, O=KDE, L=Chuo-ku, ST=Tokyo, C=jp
signed by the bundled Konami "2 Prod" CA root.  The app almost certainly
presents this in the TLS handshake (mTLS); a browser cannot, which is exactly
why the phone's browser got 500 while the app works.
"""
from __future__ import annotations

import base64
import socket
import ssl
import sys

sys.path.insert(0, r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work")

from cryptography import x509
from cryptography.hazmat.primitives import serialization

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
HOST = "pes22-game.cs.konami.net"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
FORM = "application/x-www-form-urlencoded"
BODY = open("getserverenv_body.bin", "rb").read()


def extract(begin: bytes) -> bytes:
    data = open(SO, "rb").read()
    st = data.find(begin)
    end = data.find(b"-----END", st)
    end = data.find(b"-----", end + 5) + 5
    blob = data[st:end]
    mid = blob.split(begin)[1].split(b"-----END")[0]
    return base64.b64decode(bytes(c for c in mid if c not in b"\r\n \t"))


def der_to_pem(der: bytes, label: bytes) -> bytes:
    b = base64.b64encode(der)
    lines = [b[i:i + 64] for i in range(0, len(b), 64)]
    return (b"-----BEGIN " + label + b"-----\n" + b"\n".join(lines)
            + b"\n-----END " + label + b"-----\n")


data = open(SO, "rb").read()
key_der = extract(b"-----BEGIN RSA PRIVATE KEY-----")
ca_der = extract(b"-----BEGIN CERTIFICATE-----")
# the client cert is the one whose public key matches the private key
_st = 0xB0A2D2          # CN=localhost, matches the private key's public key
_e = data.find(b"-----END CERTIFICATE-----", _st)
_e = data.find(b"-----", _e + 5) + 5
_mid = data[_st:_e].split(b"-----BEGIN CERTIFICATE-----")[1].split(b"-----END")[0]
client_der = base64.b64decode(bytes(c for c in _mid if c not in b"\r\n \t"))

key_pem = der_to_pem(key_der, b"RSA PRIVATE KEY")
ca_pem = der_to_pem(ca_der, b"CERTIFICATE")
cli_pem = der_to_pem(client_der, b"CERTIFICATE")
open("client_key.pem", "wb").write(key_pem)
open("client_cert.pem", "wb").write(cli_pem)
open("ca_root.pem", "wb").write(ca_pem)

c = x509.load_der_x509_certificate(client_der)
print("client cert subject :", c.subject.rfc4514_string())
print("client cert issuer  :", c.issuer.rfc4514_string())
print("valid               :", c.not_valid_before, "->", c.not_valid_after)
print("has private key     :", c.public_key().public_numbers().n ==
      serialization.load_der_private_key(key_der, None)
      .private_numbers().public_numbers.n)


def req(path, body, ct, use_cert, alpn):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # the CA root is a pin, not a CA
    ctx.set_alpn_protocols(alpn)
    if use_cert:
        ctx.load_cert_chain(certfile="client_cert.pem", keyfile="client_key.pem")
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
    st = d.split(b"\r\n", 1)[0].decode("latin1")
    return st + "  alpn=" + str(s.selected_alpn_protocol()), d.partition(b"\r\n\r\n")[2][:400]


for msgid in ("CMD_GET_SERVER_ENV", "CMD_LOGIN"):
    path = "/pes22/gate/gate_%s.php" % msgid
    print("\n===", path)
    for use_cert in (False, True):
        for label, ct, b in (("raw msgpack", FORM, BODY),
                             ("req=<hex>", FORM,
                              b"req=" + BODY.hex().encode())):
            tag = "WITH CLIENT CERT" if use_cert else "no cert       "
            try:
                line, body = req(path, b, ct, use_cert, ["h2", "http/1.1"])
            except Exception as e:
                print("  %s %-12s ERR %s: %s" % (tag, label, type(e).__name__, e))
                continue
            flag = "   <<<<<< NOT AN ERROR" if " 500" not in line else ""
            print("  %s %-12s %s  %r%s" % (tag, label, line, body, flag))
