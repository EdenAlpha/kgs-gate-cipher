#!/usr/bin/env python3
"""Try the login chain as `method` values in every plausible casing.

The `method` key in the JSON payload is the command selector -- a payload
carrying it is looked up and rejected, while a payload without it falls through
to the default route. The `CMD_*` names are rejected, but those are the client's
internal enum names; the wire names are likely derived from them in a different
style. This tries lowerCamel, snake, kebab, dotted and the bare suffix, for the
session/login chain specifically.

A response that is neither `14` nor `CMD_END_CONNECTION` is a command reached.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

CHAIN = [
    ("CMD_GET_SESSION_ID", "getSessionId"),
    ("CMD_CONNECT_GRPC", "connectGrpc"),
    ("CMD_CREATE_USER", "createUser"),
    ("CMD_LOGIN", "login"),
    ("CMD_AUTH_XSTS", "authXsts"),
    ("CMD_CREATEJOIN_ROOM", "createJoinRoom"),
    ("CMD_GET_ROOM_INFO", "getRoomInfo"),
    ("CMD_SEND_RECRUIT_CODE", "sendRecruitCode"),
]


def forms(name, hint):
    snake = name[4:].lower() if name.startswith("CMD_") else name.lower()
    camel = snake.split("_")[0] + "".join(
        w.capitalize() for w in snake.split("_")[1:])
    pascal = camel.capitalize()
    out = [name, snake, camel, pascal, snake.replace("_", "-"),
           snake.replace("_", ""), hint, name.lower(),
           snake.split("_")[0], snake.split("_")[-1]]
    seen, res = set(), []
    for x in out:
        if x and x not in seen:
            seen.add(x)
            res.append(x)
    return res


def probe(method):
    try:
        r = call("/", json.dumps({"method": method}), 0, str(uuid.uuid4()),
                 settle=2.5)
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
        cmd, res = dec.get("id") or "", (dec.get("res") or "")[:70]
    return st, gm, cmd, res


def main() -> int:
    print("A. chain commands as `method`, many casings\n")
    reached = []
    for name, hint in CHAIN:
        for f in forms(name, hint):
            st, gm, cmd, res = probe(f)
            if st == "14":
                continue                      # recognised key, unknown value
            if cmd and cmd != "CMD_END_CONNECTION":
                print("  method=%-26s -> cmd=%-24s %s   <<<<<< REAL"
                      % (f, cmd, res[:50]), flush=True)
                reached.append((f, cmd, res))
        print("  %-24s done" % name, flush=True)

    print("\nB. the same values as a `path`, for comparison\n")
    for name, hint in CHAIN[:4]:
        for f in forms(name, hint)[:4]:
            st, gm, cmd, res = (None, "", "", "")
            try:
                r = call("/" + f, "{}", 0, str(uuid.uuid4()), settle=2.0)
                for _fl, h in r["headers"]:
                    if "grpc-status" in h:
                        st = h["grpc-status"]
            except Exception:
                pass
            if st not in (None, "14"):
                print("  path=/%-24s -> grpc=%s" % (f, st), flush=True)

    print("\nreached: %d" % len(reached))
    for f, cmd, res in reached:
        print("  %-28s %s  %s" % (f, cmd, res))
    if not reached:
        print("\nNo casing of the CMD_* names is accepted as a `method`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
