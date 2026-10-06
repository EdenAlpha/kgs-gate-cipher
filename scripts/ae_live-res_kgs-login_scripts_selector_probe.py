#!/usr/bin/env python3
"""Two untried placements for the command selector.

`path="/"` resolves and the server answers with
`CommandResponse{id: "CMD_END_CONNECTION", res: '{"result":"NOERR"}'}`.

Note what that means: we sent `id = <a random UUID>` and the response came
back with `id = CMD_END_CONNECTION`. So the response `id` is **not** an echo —
it is the command the server actually dispatched, and with an unrecognised
selector it fell through to the default terminator.

That leaves two placements never tried:

  * **`id` is the selector.** Put `CMD_GET_SESSION_ID` in field 1 with
    `path="/"` and see whether the dispatched command changes.
  * **`req` is the selector.** Keep `path="/"` and vary the JSON payload, in
    case the route is generic and the body names the action.

Either would mean the command table is reachable without knowing the route
paths at all. A response whose `id` is anything other than
`CMD_END_CONNECTION` is a real command reached, and is printed in full.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import (call, command_request, command_response, connect,  # noqa: E402
                        read_frames, RPC, HOST, PORT, ls, frame)

CHAIN = ["CMD_GET_SESSION_ID", "CMD_CONNECT_GRPC", "CMD_CREATE_USER",
         "CMD_LOGIN", "CMD_AUTH_XSTS", "CMD_CREATEJOIN_ROOM",
         "CMD_GET_ROOM_INFO", "CMD_SEND_RECRUIT_CODE"]


def show(label, path, req_id, payload, pack=0):
    try:
        r = call(path, payload, pack, req_id, settle=3.0)
    except Exception as e:
        print("  %-52s ERROR %s" % (label, e))
        return None
    st, gm = "-", ""
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
    tag = ""
    if cmd and cmd != "CMD_END_CONNECTION":
        tag = "   <<<<<< REAL COMMAND"
    print("  %-52s -> grpc=%-4s cmd=%-22s %s%s"
          % (label[:52], st, cmd, res[:40], tag))
    return cmd, res


def main() -> int:
    print("A. command name in the `id` field (1), path kept at \"/\"\n")
    for c in CHAIN:
        show("id=%s" % c, "/", c, "{}")

    print("\nB. payload selectors, path kept at \"/\"\n")
    payloads = [
        '{"cmd":"CMD_GET_SESSION_ID"}',
        '{"command":"CMD_GET_SESSION_ID"}',
        '{"name":"CMD_GET_SESSION_ID"}',
        '{"id":"CMD_GET_SESSION_ID"}',
        '{"path":"CMD_GET_SESSION_ID"}',
        '{"type":"CMD_GET_SESSION_ID"}',
        '{"method":"CMD_GET_SESSION_ID"}',
        '["CMD_GET_SESSION_ID"]',
        '"CMD_GET_SESSION_ID"',
        json.dumps({"cmd": "CMD_GET_SESSION_ID", "params": {}}),
    ]
    for p in payloads:
        show("req=%s" % p[:44], "/", str(uuid.uuid4()), p)

    print("\nC. command name in `id`, path also as the name\n")
    for c in CHAIN[:5]:
        show("path=/%s id=%s" % (c, c), "/" + c, c, "{}")

    print("\nD. both id and payload, path \"/\"\n")
    for c in CHAIN[:5]:
        show("id=%s + req" % c, "/", c,
             json.dumps({"cmd": c, "params": {}}))

    print("\nE. a raw CommandRequest with ONLY id set (no path)\n")
    try:
        s = connect()
        m = command_request("CMD_GET_SESSION_ID", "", "", 0)
        s.sendall(frame(0, 0x1, 1, b"\x00" + len(m).to_bytes(4, "big") + m))
        r = read_frames(s, 4.0)
        for _f, h in r["headers"]:
            print("   headers: %s" % {k: unquote_plus(v) if k == "grpc-message"
                                      else v for k, v in h.items()})
        if r["data"]:
            mlen = int.from_bytes(r["data"][1:5], "big")
            print("   CommandResponse: %s"
                  % command_response(r["data"][5:5 + mlen]))
        else:
            print("   (no data)")
        s.close()
    except Exception as e:
        print("   ERROR %s" % e)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
