#!/usr/bin/env python3
"""Present the client identity as a proper CERTIFICATE CHAIN.

Earlier tests sent only the leaf (CN=localhost).  If the server validates it
against its CA root and fails, PHP sees SSL_CLIENT_VERIFY=FAILED and fatals
-- a blank 500, exactly what we have been getting from a browser (no cert)
and from a leaf-only client.

  leaf  0xb0a2d2  CN=localhost, OU=2 Prod, O=KDE, ...
  CA    0x9d9bc5  CN=CA root,   OU=2 Prod, O=KDE, ...   (issuer of the leaf)

The chain file must be leaf first, then issuer.
"""
from __future__ import annotations

import base64
import re
import socket
import ssl

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
HOST = "pes22-game.cs.konami.net"
FORM = "application/x-www-form-urlencoded"
BODY = open("getserverenv_body.bin", "rb").read()

data = open(SO, "rb").read()


def pem(der: bytes, label: bytes) -> bytes:
    b = base64.b64encode(der)
    return (b"-----BEGIN " + label + b"-----\n"
            + b"\n".join(b[i:i + 64] for i in range(0, len(b), 64))
            + b"\n-----END " + label + b"-----\n")


def blob_at(st: int, label: bytes) -> bytes:
    # the stored base64 can contain "-----" itself, so parse via regex
    start = data.find(b"-----BEGIN " + label + b"-----", st)
    m = re.search(b"-----BEGIN " + label + b"-----.*?-----END " + label
                  + b"-----", data[start:], re.S)
    mid = m.group(0).split(b"-----BEGIN ")[1].split(b"-----END")[0]
    b64 = bytes(c for c in mid if c not in b"\r\n \t")
    b64 += b"=" * (-len(b64) % 4)          # stored unpadded
    return base64.b64decode(b64)


# client_cert.pem / ca_root.pem / client_key.pem were written earlier and
# verified (4096-bit RSA key matching the leaf).  Reuse them.
leaf_pem = open("client_cert.pem", "rb").read()
ca_pem = open("ca_root.pem", "rb").read()
key_pem = open("client_key.pem", "rb").read()

# leaf first, then issuer: the order OpenSSL requires for a chain
chain = leaf_pem + ca_pem
open("chain.pem", "wb").write(chain)
open("chain_key.pem", "wb").write(key_pem)
print("wrote chain.pem (leaf + CA root) and chain_key.pem\n")


def attempt(path, body, ct, certfiles, tlsver, label):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    if tlsver:
        ctx.minimum_version = tlsver
        ctx.maximum_version = tlsver
    if certfiles:
        ctx.load_cert_chain(*certfiles)
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    L = [f"POST {path} HTTP/1.1", f"Host: {HOST}", "Accept: */*",
         "Connection: close"]
    if ct:
        L.append("Content-Type: " + ct)
    L.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    s.settimeout(25)
    d = b""
    while len(d) < 65536:
        b = s.recv(8192)
        if not b:
            break
        d += b
    ver, cipher = s.version(), s.cipher()[0]
    s.close()
    st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return (f"{label:34s} {st}  [{ver}/{cipher}]  "
            f"{d.partition(chr(13).encode()+chr(10).encode()*2)[2][:160]!r}")


path = "/pes22/gate/gate_CMD_GET_SERVER_ENV.php"
print("=== /pes22/gate/gate_CMD_GET_SERVER_ENV.php ===")
cases = [
    ("no client cert", None, None),
    ("leaf only", ("client_cert.pem", "client_key.pem"), None),
    ("CHAIN (leaf + CA root)", ("chain.pem", "chain_key.pem"), None),
    ("CHAIN + TLS1.2", ("chain.pem", "chain_key.pem"), ssl.TLSVersion.TLSv1_2),
    ("CHAIN + TLS1.3", ("chain.pem", "chain_key.pem"), ssl.TLSVersion.TLSv1_3),
]
for label, cf, tv in cases:
    try:
        print("  " + attempt(path, BODY, FORM, cf, tv, label))
    except Exception as e:
        print(f"  {label:34s} ERR {type(e).__name__}: {e}")

path2 = "/pes22/gate/gate_CMD_LOGIN.php"
print("\n=== /pes22/gate/gate_CMD_LOGIN.php ===")
for label, cf, tv in cases:
    try:
        print("  " + attempt(path2, BODY, FORM, cf, tv, label))
    except Exception as e:
        print(f"  {label:34s} ERR {type(e).__name__}: {e}")
