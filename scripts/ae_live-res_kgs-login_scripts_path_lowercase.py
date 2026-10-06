#!/usr/bin/env python3
"""Try the login-chain commands as lowercase URL paths.

The response's `id` is the command name the server dispatched, and `path="/"`
resolves to `CMD_END_CONNECTION`. If the routes are derived from the same
identifiers, the natural form is the command name lowercased under a path
separator. This tries the session/login chain that way, plus a few structural
variants, and prints any path that resolves to something other than
`CMD_END_CONNECTION` — that would be the first real command reached.
"""
from __future__ import annotations

import os
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

CHAIN = [
    "CMD_GET_SESSION_ID", "CMD_CONNECT_GRPC", "CMD_CREATE_USER", "CMD_LOGIN",
    "CMD_AUTH_XSTS", "CMD_AUTH_GOOGLE", "CMD_AUTH_STEAM", "CMD_AUTH_SWITCH",
    "CMD_GET_USER_INFO", "CMD_CHECK_MATCH_ENABLE", "CMD_CREATEJOIN_ROOM",
    "CMD_GET_ROOM_INFO", "CMD_SEND_RECRUIT_CODE", "CMD_END_CONNECTION",
    "CMD_ERROR", "CMD_ADD_SCORE", "CMD_CREATE_SQUAD", "CMD_GET_ROOM_LIST",
    "CMD_SEARCH_USER", "CMD_GET_USER_COMPE", "CMD_CHECK_STRING",
]


def variants(name):
    low = name.lower()
    no_prefix = low[4:] if low.startswith("cmd_") else low
    yield "/" + low
    yield "/" + no_prefix
    yield "/" + no_prefix.replace("_", "-")
    yield "/v1/" + no_prefix
    yield "/api/" + no_prefix
    yield "/" + name


def probe(path):
    try:
        r = call(path, "{}", 0, str(uuid.uuid4()), settle=2.5)
    except Exception as e:
        return None, str(e), b""
    st, gm = "-", ""
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = unquote_plus(h.get("grpc-message", ""))
    return st, gm, r["data"]


def describe(data):
    if len(data) < 5:
        return "", ""
    mlen = int.from_bytes(data[1:5], "big")
    dec = command_response(data[5:5 + mlen])
    return dec.get("id") or "", (dec.get("res") or "")[:80]


def main() -> int:
    interesting = []
    n = 0
    for name in CHAIN:
        for p in variants(name):
            n += 1
            st, gm, data = probe(p)
            cmd, res = describe(data)
            if st in (None, "14"):
                continue
            tag = ""
            if cmd and cmd != "CMD_END_CONNECTION":
                tag = "   <<<<<< REAL COMMAND"
                interesting.append((p, cmd, res))
            print("  %-40s -> grpc=%-4s cmd=%-22s %s%s"
                  % (p[:40], st, cmd, res[:40], tag), flush=True)
    print("\nprobed %d paths" % n)
    if interesting:
        print("\n=== COMMANDS REACHED ===")
        for p, cmd, res in interesting:
            print("  %-40s -> %s   %s" % (p, cmd, res))
    else:
        print("\nNothing resolved beyond the default route. The command paths")
        print("are not derived from the CMD_* identifiers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
