#!/usr/bin/env python3
"""Ask the NTL host (the one GateInfo already talks to) for the Cmd*.php files.

The CS host answers 404 "File not found." for every Cmd*.php.  GateInfo works
against ntl.service.konami.net, so the commands may simply live over there.
"""
from __future__ import annotations

import http.client
import sys

HOST = "ntl.service.konami.net"

PATHS = [
    "/ntl/api/GateInfo.php",            # control: we know this one exists
    "/ntl/api/CmdGetServerEnv.php",
    "/ntl/api/CmdLogin.php",
    "/ntl/api/CmdCreateJoinRoom.php",
    "/ntl/api/CmdGetKgsGuestLoginToken.php",
    "/ntl/api/gate.php",
    "/ntl/GateInfo.php",
    "/ntl/api/",
    "/",
]


def hit(path: str) -> str:
    c = http.client.HTTPConnection(HOST, 80, timeout=20)
    try:
        c.request("GET", path)
        r = c.getresponse()
        body = r.read(400)
        return f"{r.status} {r.reason}  {dict(r.getheaders()).get('Content-Type','')}\n      {body!r}"
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"
    finally:
        c.close()


def main() -> int:
    for p in PATHS:
        print(f"--- {p}", flush=True)
        print(f"    {hit(p)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
