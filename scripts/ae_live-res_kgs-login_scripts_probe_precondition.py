#!/usr/bin/env python3
"""If the PHP fatals before reading the body, it is on something it reads
FIRST: a query parameter or a header.  A missing one gives a TypeError on
undefined index -> blank 500.

Real evidence for the naming convention: the capture's plaintext ReportLog
POST (ntl.service.konami.net/ntl/api/PES2022/ReportLog.php):

    type=pds&prefix=1790386120_2_0000...0000_0000__e01a7766...83d8_0
           &ver=4&dat=2323204e544c496e666f...

i.e. type=, prefix=, ver=, dat=<hex>.  Same family as GateInfo's req=<hex>.

Also test the header set the game's own header builder (0x7d03e10) emits.
"""
from __future__ import annotations

import socket
import ssl

HOST = "pes22-game.cs.konami.net"
FORM = "application/x-www-form-urlencoded"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
HEX = open("real_body.bin", "rb").read().hex()


def post(path, body=b"", ct=FORM, extra_headers=(), query=""):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    L = [f"POST {path}{query} HTTP/1.1", f"Host: {HOST}", f"User-Agent: {UA}",
         "Accept: */*", "Connection: close", "Content-Type: " + ct]
    for e in extra_headers:
        L.append(e)
    L.append(f"Content-Length: {len(body)}")
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    s.settimeout(25)
    d = b""
    while len(d) < 65536:
        b = s.recv(8192)
        if not b:
            break
        d += b
    s.close()
    st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    bd = d.partition(b"\r\n\r\n")[2]
    return st, bd


def interesting(st, bd):
    """A blank 500 is the baseline.  Anything else is news."""
    blank = (bd.strip() in (b"", b"0\r\n\r\n", b"0"))
    return ("500" in st and blank) is False


PREFIX = "1790386120_2_00000000000000000000000000000000_0000__e01a7766eb9df741b603aef191fb83d8_0"

CASES = [
    # ReportLog's observed convention
    ("type+prefix+ver+dat", b"type=pde&prefix=" + PREFIX.encode()
     + b"&ver=4&dat=" + HEX.encode()),
    ("type+ver+dat", b"type=pde&ver=4&dat=" + HEX.encode()),
    ("prefix+dat", b"prefix=" + PREFIX.encode() + b"&dat=" + HEX.encode()),
    ("type=CMD_LOGIN+dat", b"type=CMD_LOGIN&ver=4&dat=" + HEX.encode()),
    ("type=cmd+dat json", b"type=cmd&ver=4&dat="
     + b'{"msgid":"CMD_LOGIN"}'.hex().encode()),
]

QUERIES = [
    "?msgid=CMD_LOGIN",
    "?msg=CMD_LOGIN",
    "?cmd=CMD_LOGIN",
    "?type=CMD_LOGIN",
    "?req=CMD_LOGIN",
    "?api=CMD_LOGIN",
    "?func=CMD_LOGIN",
    "?action=CMD_LOGIN",
    "?m=CMD_LOGIN",
    "?p=CMD_LOGIN",
    "?ver=4",
    "?ver=4&lang=en®ion=US",
]

HDRSETS = [
    ("SOAP MAN+M-POST", [
        'Content-Type: text/xml; charset="utf-8"',
        'MAN: "http://schemas.xmlsoap.org/soap/envelope/"; ns=01',
    ]),
    ("SoapAction", ['SoapAction: "CMD_LOGIN"']),
    ("X-Konami-Version", ["X-Konami-Version: 6.0.1"]),
    ("X-Api-Level", ["X-Api-Level: 4"]),
    ("X-Device-Uuid", ["X-Device-Uuid: e01a7766eb9df741b603aef191fb83d8"]),
    ("X-Uid", ["X-Uid: e01a7766eb9df741b603aef191fb83d8"]),
    ("X-Session", ["X-Session: 1790386120"]),
    ("Accept-Encoding identity", ["Accept-Encoding: identity"]),
    ("Expect empty", ["Expect: "]),
]

# nginx routes by Host header: a different Host hits a different server block
# with a different PHP config.  The app may send one we have not tried.
HOSTVARS = [
    "pes22-game.cs.konami.net",
    "pes22-game.cs.konami.net:443",
    "pes22-game.konami.net",
    "pes22.cs.konami.net",
    "game.cs.konami.net",
    "cs.konami.net",
    "pes22-game",
    "localhost",
    "pes22-game.cs.konami.net\r\nX-Forwarded-Host: pes22-game.cs.konami.net",
]


def post_hostvar(host, path, body):
    """POST with an explicit Host header value."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    L = [f"POST {path} HTTP/1.1", f"Host: {host}", f"User-Agent: {UA}",
         "Accept: */*", "Connection: close", f"Content-Type: {FORM}",
         f"Content-Length: {len(body)}"]
    s.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    s.settimeout(25)
    d = b""
    while len(d) < 65536:
        b = s.recv(8192)
        if not b:
            break
        d += b
    s.close()
    st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
    return st, d.partition(b"\r\n\r\n")[2]

print("=== form-field cases (ReportLog convention) ===")
for label, body in CASES:
    for msgid in ("CMD_LOGIN",):
        try:
            st, bd = post(f"/pes22/gate/gate_{msgid}.php", body)
        except Exception as e:
            print(f"  {label:24s} ERR {type(e).__name__}: {e}")
            continue
        mark = "   <<<<<< CHANGED" if interesting(st, bd) else ""
        print(f"  {label:24s} {st}  {bd[:160]!r}{mark}")

print("\n=== query-parameter cases (GET + POST empty) ===")
for q in QUERIES:
    for method_body, tag in ((b"", "POST empty"), (b"", "GET")):
        try:
            if tag == "GET":
                ctx = ssl.create_default_context()
                ctx.set_alpn_protocols(["http/1.1"])
                s = ctx.wrap_socket(socket.create_connection((HOST, 443),
                                    timeout=25), server_hostname=HOST)
                s.sendall((f"GET /pes22/gate/gate_CMD_LOGIN.php{q} HTTP/1.1\r\n"
                           f"Host: {HOST}\r\nConnection: close\r\n\r\n").encode())
                s.settimeout(25)
                d = b""
                while len(d) < 65536:
                    b = s.recv(8192)
                    if not b:
                        break
                    d += b
                s.close()
                st = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
                bd = d.partition(b"\r\n\r\n")[2]
            else:
                st, bd = post(f"/pes22/gate/gate_CMD_LOGIN.php", method_body,
                              FORM, query=q)
        except Exception as e:
            print(f"  {q:26s} {tag:10s} ERR {type(e).__name__}")
            continue
        mark = "   <<<<<< CHANGED" if interesting(st, bd) else ""
        print(f"  {q:26s} {tag:10s} {st}  {bd[:120]!r}{mark}")

print("\n=== header-set cases ===")
for label, hdrs in HDRSETS:
    try:
        st, bd = post("/pes22/gate/gate_CMD_LOGIN.php",
                      b"type=cmd&dat=" + HEX.encode(), FORM, hdrs)
    except Exception as e:
        print(f"  {label:24s} ERR {type(e).__name__}")
        continue
    mark = "   <<<<<< CHANGED" if interesting(st, bd) else ""
    print(f"  {label:24s} {st}  {bd[:160]!r}{mark}")

print("\n=== Host header variants (nginx routes on Host) ===")
for host in HOSTVARS:
    label = host.replace("\r\n", " / ")
    try:
        st, bd = post_hostvar(host, "/pes22/gate/gate_CMD_LOGIN.php",
                              b"type=cmd&dat=" + HEX.encode())
    except Exception as e:
        print(f"  {label:40s} ERR {type(e).__name__}")
        continue
    mark = "   <<<<<< CHANGED" if interesting(st, bd) else ""
    print(f"  {label:40s} {st}  {bd[:120]!r}{mark}")

    # and one bare GET per host to see if the vhost exists at all
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                            server_hostname=HOST)
        s.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                   f"Connection: close\r\n\r\n").encode())
        s.settimeout(25)
        d = b""
        while len(d) < 8192:
            b = s.recv(4096)
            if not b:
                break
            d += b
        s.close()
        st2 = d.split(b"\r\n", 1)[0].decode("latin1") if d else "EMPTY"
        if "404" not in st2 and "403" not in st2:
            print(f"      GET / under this Host -> {st2}   <<<<<< vhost differs")
    except Exception:
        pass
