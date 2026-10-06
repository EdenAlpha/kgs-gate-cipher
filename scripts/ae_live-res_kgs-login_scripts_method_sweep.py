#!/usr/bin/env python3
"""Sweep the `method` key in the JSON payload.

The discriminator: with `path="/"` every payload tried returned the default
`CMD_END_CONNECTION` **except** `{"method": "CMD_GET_SESSION_ID"}`, which came
back `grpc-status: 14 UNAVAILABLE`. A payload the server does not understand
falls through to the default route; one that names a `method` it does not know
is rejected. So the payload selects the command, and `method` is the key.

This sweeps the login chain and the full `CMD_*` vocabulary through that key, at
`path="/"`, and prints anything that is not the default terminator. A response
that is neither `14` nor `CMD_END_CONNECTION` is a command actually reached.
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
CHAIN = ["CMD_GET_SESSION_ID", "CMD_CONNECT_GRPC", "CMD_CREATE_USER",
         "CMD_LOGIN", "CMD_AUTH_XSTS", "CMD_CREATEJOIN_ROOM",
         "CMD_GET_ROOM_INFO", "CMD_SEND_RECRUIT_CODE"]


def probe(method, key="method", path="/", extra=None):
    payload = {key: method}
    if extra:
        payload.update(extra)
    try:
        r = call(path, json.dumps(payload), 0, str(uuid.uuid4()), settle=2.5)
    except Exception as e:
        return None, str(e), "", ""
    st, gm = None, ""
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = unquote_plus(h.get("grpc-message", ""))
    cmd, res = "", ""
    d = r["data"]
    if len(d) >= 5:
        mlen = int.from_bytes(d[1:5], "big")
        dec = command_response(d[5:5 + mlen])
        cmd, res = dec.get("id") or "", (dec.get("res") or "")[:80]
    return st, gm, cmd, res


def main() -> int:
    d = open(SO, "rb").read()
    names = sorted(set(m.group(0).decode()
                       for m in re.finditer(rb"CMD_[A-Z0-9_]{2,48}", d)))
    print("A. chain commands via payload key 'method', path=\"/\"\n")
    for c in CHAIN:
        st, gm, cmd, res = probe(c)
        tag = ""
        if cmd and cmd != "CMD_END_CONNECTION":
            tag = "   <<<<<< REAL"
        elif st == "14":
            tag = "   (rejected: recognised key, unknown method)"
        print("  %-28s -> grpc=%-4s cmd=%-20s %s%s"
              % (c, st, cmd, res[:34], tag), flush=True)

    print("\nB. the whole CMD_* vocabulary (%d names)\n" % len(names))
    hits, rejected = [], 0
    n = 0
    for c in names:
        n += 1
        st, gm, cmd, res = probe(c)
        if st == "14":
            rejected += 1
            continue
        if cmd and cmd != "CMD_END_CONNECTION":
            print("  %-30s -> grpc=%-4s cmd=%-24s %s   <<<<<< REAL"
                  % (c, st, cmd, res[:50]), flush=True)
            hits.append((c, st, cmd, res))
        if n % 40 == 0:
            print("     ...%d/%d, %d rejected, %d real"
                  % (n, len(names), rejected, len(hits)), flush=True)

    print("\nswept %d: %d rejected, %d resolved to a real command"
          % (n, rejected, len(hits)))
    if hits:
        print("\n=== COMMANDS REACHED ===")
        for c, st, cmd, res in hits:
            print("  %-30s %s  %s" % (c, cmd, res))
    else:
        print("\nNo CMD_* name is accepted as a `method`. The method names are")
        print("something else -- the game's own request is still the source.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
