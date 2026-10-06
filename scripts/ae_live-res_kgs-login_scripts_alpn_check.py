#!/usr/bin/env python3
"""What protocols does the gate endpoint negotiate?"""
from __future__ import annotations

import socket
import ssl

HOST = "pes22-game.cs.konami.net"
for alpn in (["h2", "http/1.1"], ["http/1.1"], ["h2"]):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(alpn)
    try:
        s = ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=20),
                            server_hostname=HOST)
        print(f"offer {alpn} -> negotiated {s.selected_alpn_protocol()!r} "
              f"tls={s.version()}")
        s.close()
    except Exception as e:
        print(f"offer {alpn} -> ERR {type(e).__name__}: {e}")

# certificate subject / SANs
ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.create_connection((HOST, 443), timeout=20),
                     server_hostname=HOST) as s:
    c = s.getpeercert()
    print("subject:", c.get("subject"))
    print("SANs   :", [v for k, v in c.get("subjectAltName", ())])
