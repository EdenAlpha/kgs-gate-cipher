#!/usr/bin/env python3
"""Do the servers the app ACTUALLY talked to still answer?

Today `pes22-game.cs.konami.net` resolves to 8 IPs, none of which appear in
any capture.  The June-2026 capture (a session that demonstrably worked: many
request/response records and a clean close_notify) went to three OTHER
us-west-2 hosts.  If the deployment moved, our 500s are aimed at a stale
front end.

For every candidate IP: TLS with SNI=pes22-game, print the certificate, then
POST the gate script exactly as before and print the status.
"""
from __future__ import annotations

import socket
import ssl

HOST = "pes22-game.cs.konami.net"
PATH = "/pes22/gate/gate_CMD_LOGIN.php"

CANDIDATES = [
    ("June-2026 capture", ["35.162.14.39", "184.32.162.16",
                           "44.249.229.22"]),
    ("Jan-2026 capture", ["44.228.227.149", "52.24.28.234",
                          "44.236.164.99", "54.201.205.31", "52.32.55.87",
                          "52.38.62.14", "16.144.118.86"]),
    ("Mar-2026 capture", ["13.216.208.21", "99.80.34.130", "99.80.34.181"]),
    ("today's DNS", ["184.34.183.36", "32.187.160.14", "34.208.149.190"]),
]


def cert_names(sock):
    der = sock.getpeercert(binary_form=True)
    if not der:
        return "?", []
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        cn = c.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME)
        try:
            san = c.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName)
        except Exception:
            san = []
        return (cn[0].value if cn else "?"), san
    except Exception:
        import re
        return "?", sorted({t.decode() for t in re.findall(
            rb"[a-zA-Z0-9][a-zA-Z0-9.\-]{4,60}\.konami\.[a-z]{2,3}", der)})


def probe(ip, payload):
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        with ctx.wrap_socket(socket.create_connection((ip, 443), timeout=12),
                             server_hostname=HOST) as s:
            cn, san = cert_names(s)
            req = ("POST %s HTTP/1.1\r\nHost: %s\r\n"
                   "Content-Type: application/x-www-form-urlencoded\r\n"
                   "Content-Length: %d\r\nConnection: close\r\n\r\n"
                   % (PATH, HOST, len(payload))).encode()
            s.settimeout(15)
            s.sendall(req + payload)
            d = b""
            while len(d) < 4000:
                b = s.recv(2048)
                if not b:
                    break
                d += b
        line = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
        body = d.partition(b"\r\n\r\n")[2][:80]
        return "cert=%s san=%s | %s | %r" % (cn, ",".join(san[:3]), line, body)
    except Exception as e:
        return "ERR %s: %s" % (type(e).__name__, str(e)[:90])


def main() -> int:
    try:
        payload = open("real_body.bin", "rb").read()
    except Exception:
        payload = b""
    for label, ips in CANDIDATES:
        print("=== %s ===" % label, flush=True)
        for ip in ips:
            print("  %-17s %s" % (ip, probe(ip, payload)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
