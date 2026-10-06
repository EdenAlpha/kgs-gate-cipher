#!/usr/bin/env python3
"""Send the body the GAME produced to gate.php, in every plausible wiring.

The 451 bytes below were emitted by the binary's own serializer 0x76b1b28.
We do not invent a byte -- only the transport wrapper is varied.
"""
from __future__ import annotations

import ssl
import socket
import sys

HOST = "pes22-game.cs.konami.net"

BODY = (
    b"\xde\x00\x1d\xa5msgid\xa0\xa4rqid\x00\xa7user_id\x00\xaasession_id"
    b"\xa0\xabmy_platform\xa0\xa9s_keyword\xa0\xa9auth_code\xa0\xa4hash"
    b"\xa0\xaeclient_version\xa0\xa8platform\xa0\xa6device\x81\xb1"
    b"device_identifier\xa0\xa4lang\xa0\xaccountry_code\x90\xa6region"
    b"\xa0\xa6pcspec\xa0\xb5cross_platform_option\xa0\xb2is_disable_sharing"
    b"\xa0\xaaos_version\xa0\xaamodel_name\xa0\xa8gpu_name\xa0\xa8soc_name"
    b"\xa0\xa9is_rooting\xa0\xb0phy_mem_used_mib\x00\xb5"
    b"phy_mem_available_mib\x00\xb4app_storage_used_mib\x00\xb9"
    b"app_storage_available_mib\x00\xb5data_storage_used_mib\x00\xba"
    b"data_storage_available_mib\x00\xbcpayment_store_link_send_info\x81"
    b"\xaccountry_code\xa0"
)

HEX = BODY.hex().encode()          # lowercase, same alphabet as GateInfo


def send(method: str, path: str, body: bytes, ctype: str | None,
         extra: list[str] | None = None) -> str:
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=25),
                        server_hostname=HOST)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {HOST}", "Connection: close"]
    if ctype:
        lines.append(f"Content-Type: {ctype}")
    lines.append(f"Content-Length: {len(body)}")
    if extra:
        lines.extend(extra)
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    data = b""
    while len(data) < 16384:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
    head, _, bd = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin1")
    return f"{status}   body={bd[:200]!r}"


FORM = "application/x-www-form-urlencoded"
CASES = [
    ("POST", "/pes22/gate.php", b"req=" + HEX, FORM),
    ("POST", "/pes22/gate.php", b"req=" + HEX, "application/octet-stream"),
    ("POST", "/pes22/gate.php", BODY, "application/octet-stream"),
    ("POST", "/pes22/gate.php", BODY, "application/msgpack"),
    ("POST", "/pes22/gate.php", BODY, FORM),
    ("POST", "/pes22/gate.php", BODY, None),
    ("POST", "/pes22/gate.php", b"req=" + HEX, None),
    ("GET", "/pes22/gate.php?req=" + HEX.decode(), None, None),
]


def main() -> int:
    print(f"[len] body={len(BODY)} hex={len(HEX)}", flush=True)
    for m, p, b, ct in CASES:
        label = f"{m} {p[:40]} ct={ct} blen={len(b)}"
        try:
            print(f"--- {label}", flush=True)
            print(f"    {send(m, p, b if b is not None else b'', ct)}",
                  flush=True)
        except Exception as e:
            print(f"    ERR {type(e).__name__}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
