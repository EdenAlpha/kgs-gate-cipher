#!/usr/bin/env python3
"""1) Are the phone's LB (54.218.129.95) and our pool the SAME service?
   Compare cert, ALPN, HTTP/1.1 vs h2 behaviour, and live gRPC status per IP.
2) Parse the phone's actual ClientHello from the capture for comparison."""
from __future__ import annotations

import hashlib
import socket
import ssl
import sys
import time

import dpkt
import h2.config
import h2.connection
import h2.events

HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"
CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
           "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
PHONE_IP = "54.218.129.95"
PCAP = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
        r"\168ed698-75b8-4a9d-8e53-a7c6570a633e"
        r"\PCAPdroid_29_Sep_10_31_15.pcap")


def ctx(protos):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.maximum_version = ssl.TLSVersion.TLSv1_2
    c.set_alpn_protocols(protos)
    c.set_ciphers(CIPHERS)
    return c


def cert_info(ip: str) -> str:
    try:
        s = ctx(["h2"]).wrap_socket(
            socket.create_connection((ip, 443), timeout=6), server_hostname=HOST)
    except Exception as e:
        return "connect-fail %s" % e
    der = s.getpeercert(binary_form=True)
    alpn = s.selected_alpn_protocol()
    s.close()
    # subject/SAN need decoded dict; use decoded too
    try:
        s = ctx(["h2"]).wrap_socket(
            socket.create_connection((ip, 443), timeout=6), server_hostname=HOST)
        dec = s.getpeercert()
        s.close()
        subj = dict(x[0] for x in dec.get("subject", ())).get("commonName", "?")
        sans = [v for k, v in dec.get("subjectAltName", ())]
    except Exception:
        subj, sans = "?", []
    return "alpn=%s sha256=%s cn=%s san=%s" % (
        alpn, hashlib.sha256(der).hexdigest()[:16], subj, ",".join(sans[:4]))


def grpc_status(ip: str) -> str:
    t0 = time.time()
    try:
        s = ctx(["grpc-exp", "h2"]).wrap_socket(
            socket.create_connection((ip, 443), timeout=6), server_hostname=HOST)
    except Exception as e:
        return "connect-fail %s" % e
    s.settimeout(6)
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    conn.send_headers(1, [
        (":method", "POST"), (":scheme", "https"), (":authority", HOST),
        (":path", METHOD),
        ("content-type", "application/grpc"), ("te", "trailers"),
        ("user-agent", "grpc-c/1.0 (android; arm64; pesam)"),
    ], end_stream=False)
    conn.send_data(1, b"\x00\x00\x00\x00\x00", end_stream=True)
    s.sendall(conn.data_to_send())
    out = "no-response"
    end = time.time() + 6
    while time.time() < end:
        try:
            d = s.recv(65535)
        except socket.timeout:
            break
        if not d:
            out = "eof"
            break
        for ev in conn.receive_data(d):
            if isinstance(ev, h2.events.ResponseReceived):
                h = dict(ev.headers)
                out = "%.2fs %s %s %s" % (
                    time.time() - t0, h.get(":status"),
                    h.get("grpc-status", "-"), h.get("grpc-message", "-"))
        s.sendall(conn.data_to_send())
    s.close()
    return out


def http11_status(ip: str) -> str:
    try:
        s = ctx(["http/1.1"]).wrap_socket(
            socket.create_connection((ip, 443), timeout=6), server_hostname=HOST)
        s.settimeout(6)
        s.sendall(("POST /pes22/gate/gate_1.php HTTP/1.1\r\nHost: %s\r\n"
                   "Content-Length: 7\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                   "Connection: close\r\n\r\nreq=abc" % HOST).encode())
        buf = b""
        while True:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
            if b"\r\n\r\n" in buf:
                break
        s.close()
        return buf.split(b"\r\n")[0].decode(errors="replace")
    except Exception as e:
        return "ERR %s" % e


def main() -> int:
    ips = [PHONE_IP] + sorted({a[4][0] for a in socket.getaddrinfo(
        HOST, 443, socket.AF_INET, socket.SOCK_STREAM)})
    print("== per-IP identity + live status ==")
    for ip in ips:
        print("  %-16s cert: %s" % (ip, cert_info(ip)))
        print("  %-16s grpc: %s" % ("", grpc_status(ip)))
        print("  %-16s h1.1: %s" % ("", http11_status(ip)))
    print("\n== phone's ClientHello from capture ==")
    parse_phone_ch()
    return 0


def parse_phone_ch() -> None:
    d = b""
    with open(PCAP, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)
        for ts, buf in pcap:
            try:
                ip = dpkt.ethernet.Ethernet(buf).data
            except Exception:
                continue
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP) or tcp.sport != 32912:
                continue
            d = tcp.data
            if d[:1] == b"\x16" and d[5:6] == b"\x01":
                break
        else:
            d = b""
    if not d:
        print("  CH not found")
        return
    ln = int.from_bytes(d[3:5], "big")
    body = d[9:5 + ln]
    i = 2 + 32
    i += 1 + body[i]
    cs_len = int.from_bytes(body[i:i + 2], "big"); i += 2
    ciphers = [body[j:j + 2].hex() for j in range(i, i + cs_len, 2)]
    i += cs_len
    i += 1 + body[i]
    ext_len = int.from_bytes(body[i:i + 2], "big"); i += 2
    end = i + ext_len
    exts = []
    print("  version=%s ciphers=%s" % (body[:2].hex(), ciphers))
    while i + 4 <= end:
        t = int.from_bytes(body[i:i + 2], "big")
        l = int.from_bytes(body[i + 2:i + 4], "big")
        exts.append((t, l))
        if t == 0x0010:
            v = body[i + 4:i + 4 + l]
            j = 2
            alpn = []
            while j < len(v):
                n = v[j]; j += 1
                alpn.append(v[j:j + n].decode()); j += n
            print("   ALPN:", alpn)
        if t == 0:
            v = body[i + 4:i + 4 + l]
            print("   SNI:", v[5:5 + int.from_bytes(v[3:5], "big")].decode())
        i += 4 + l
    names = {0: "SNI", 10: "groups", 11: "ecpts", 13: "sigalgs", 16: "ALPN",
             21: "padding", 22: "encrypt_then_mac", 23: "extended_ms",
             35: "session_ticket", 43: "versions", 51: "key_share",
             65281: "reneg_info", 17513: "application_settings",
             18: "signed_cert_ts", 5: "status_request"}
    print("  extensions:", [(names.get(t, t), l) for t, l in exts])
    print("  total CH bytes:", len(d))


if __name__ == "__main__":
    sys.exit(main())
