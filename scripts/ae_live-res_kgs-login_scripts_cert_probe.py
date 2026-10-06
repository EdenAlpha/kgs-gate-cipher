#!/usr/bin/env python3
"""Two direct checks on the client certificate question.

1. What IS client_cert.pem? (subject/issuer/validity/purpose extensions,
   plus the other certs in the work dir for comparison)
2. Does any Konami server ever ASK for a client certificate?  Raw TLS 1.2
   handshake per host; a CertificateRequest message (handshake type 13)
   proves mTLS is actually in play.  Absence proves the cert cannot matter
   on that host.
"""
from __future__ import annotations

import os
import random
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.backends import default_backend  # noqa: E402

CERTS = ["client_cert.pem", "chain.pem", "ca_root.pem",
         "bin_cert1.pem", "bin_cert2.pem"]

HOSTS = ["pes22-game.cs.konami.net", "ntl.service.konami.net",
         "info.service.konami.net"]


def show_cert(path: str) -> None:
    print("=== %s ===" % path)
    try:
        with open(os.path.join(HERE, path), "rb") as f:
            blob = f.read()
    except OSError as e:
        print("  missing: %s" % e)
        return
    # may hold several PEM blocks; show each
    parts = blob.split(b"-----END CERTIFICATE-----")
    n = 0
    for p in parts:
        if b"-----BEGIN CERTIFICATE-----" not in p:
            continue
        n += 1
        der = b"".join(
            l for l in p.split(b"\n")
            if l.strip() and b"BEGIN" not in l)
        import base64
        try:
            cert = x509.load_der_x509_certificate(
                base64.b64decode(der), default_backend())
        except Exception as e:
            print("  [%d] parse error: %s" % (n, e))
            continue
        print("  [%d] subject: %s" % (n, cert.subject.rfc4514_string()))
        print("  [%d] issuer : %s" % (n, cert.issuer.rfc4514_string()))
        print("  [%d] valid  : %s .. %s"
              % (n, cert.not_valid_before_utc, cert.not_valid_after_utc))
        print("  [%d] serial : %x" % (n, cert.serial_number))
        for oid_name in ("subjectAltName", "keyUsage",
                         "extendedKeyUsage", "basicConstraints"):
            try:
                ext = cert.extensions.get_extension_for_class(
                    {"subjectAltName": x509.SubjectAlternativeName,
                     "keyUsage": x509.KeyUsage,
                     "extendedKeyUsage": x509.ExtendedKeyUsage,
                     "basicConstraints": x509.BasicConstraints}[oid_name])
                print("  [%d] %s: %s" % (n, oid_name, ext.value))
            except x509.ExtensionNotFound:
                pass


def ext_u16(t: int, body: bytes) -> bytes:
    return struct.pack(">HH", t, len(body)) + body


def client_hello(host: str) -> bytes:
    rnd = bytes(random.getrandbits(8) for _ in range(32))
    ciphers = bytes.fromhex("c02bc02cc02fc03000ff")
    sni_name = host.encode()
    sni = struct.pack(">H", len(sni_name) + 3) + b"\x00" + \
        struct.pack(">H", len(sni_name)) + sni_name
    sigalgs = bytes.fromhex("04010403050306030804080508060601")
    exts = (ext_u16(0, sni) + ext_u16(13, struct.pack(">H", len(sigalgs))
                                     + sigalgs))
    body = (b"\x03\x03" + rnd + b"\x00"
            + struct.pack(">H", len(ciphers)) + ciphers
            + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


HNAMES = {2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange",
          13: "CertificateRequest", 14: "ServerHelloDone"}


def probe_host(host: str) -> None:
    print("\n=== %s : server handshake ===" % host)
    ip = socket.gethostbyname(host)
    s = socket.create_connection((ip, 443), timeout=10)
    s.settimeout(10)
    try:
        s.sendall(client_hello(host))
        buf = b""
        seen: list[tuple[str, int]] = []
        version = None
        done = False
        while not done:
            chunk = s.recv(16384)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 5:
                rtype = buf[0]
                rlen = struct.unpack(">H", buf[3:5])[0]
                if len(buf) < 5 + rlen:
                    break
                rec = buf[5:5 + rlen]
                buf = buf[5 + rlen:]
                if rtype == 0x16:                      # handshake
                    i = 0
                    while i + 4 <= len(rec):
                        htype = rec[i]
                        hlen = int.from_bytes(rec[i + 1:i + 4], "big")
                        frag = rec[i + 4:i + 4 + hlen]
                        i += 4 + hlen
                        seen.append((HNAMES.get(htype, "hs#%d" % htype),
                                     len(frag)))
                        if htype == 2 and len(frag) >= 2:
                            version = frag[0:2].hex()
                            if len(frag) > 34 + frag[34]:
                                version += " (+ext, check supported_versions)"
                        if htype == 13:
                            # CertificateRequest body: cert_types + sigalgs +
                            # CA list; print CA names count
                            print("  *** CertificateRequest SEEN ***")
                        if htype == 14:
                            done = True
                elif rtype == 0x15:
                    print("  ALERT %r" % rec)
                    done = True
        print("  server_version=%s" % version)
        print("  messages: %s"
              % ", ".join("%s(%dB)" % t for t in seen))
        print("  cert-requested: %s"
              % any(t[0] == "CertificateRequest" for t in seen))
    except Exception as e:
        print("  ERR %s: %s" % (type(e).__name__, str(e)[:100]))
    finally:
        s.close()


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "hostsonly":
        for h in HOSTS:
            probe_host(h)
        return 0
    for c in CERTS:
        show_cert(c)
    for h in HOSTS:
        probe_host(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
