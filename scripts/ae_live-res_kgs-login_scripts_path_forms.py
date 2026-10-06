#!/usr/bin/env python3
"""Does `path` need a qualified form, and does the payload shape matter?

The schema is correct and the server answers `14 UNAVAILABLE` for a bare
`CMD_*` name, which it also does for a name that does not exist. Two
possibilities remain:

  * the command name is right but the *form* is wrong (a leading slash, a
    package-qualified path, a different separator);
  * the name is wrong entirely, in which case the 384-name sweep will find it.

This varies the form while holding one candidate name fixed, and also varies
the `req` payload and the `id`, so that whichever knob the server actually
inspects shows up as a status other than 14.

`id` is included in the variants because it is echoed back in
`CommandResponse.id`: if the server ever answers at all, a matching id proves
the request was correlated and therefore understood.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_request, connect, read_frames  # noqa: E402
from decode_capture import hpack_decode  # noqa: E402

NAME = "CMD_GET_SESSION_ID"


def st_of(r):
    st, gm = "-", ""
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = unquote_plus(h.get("grpc-message", ""))
    return st, gm, r["data"]


def show(label, **kw):
    try:
        r = call(kw.pop("path"), kw.pop("payload", "{}"),
                 kw.pop("pack_mode", 0), kw.pop("req_id", None) or str(uuid.uuid4()))
    except Exception as e:
        print("  %-52s ERROR %s: %s" % (label, type(e).__name__, e))
        return None
    st, gm, data = st_of(r)
    extra = ""
    if len(data) >= 5:
        extra = " data=%dB %s" % (len(data), data[5:29].hex())
    print("  %-52s -> grpc=%-4s %s%s" % (label, st, gm[:44], extra))
    return r


def main() -> int:
    print("A. path FORM, holding the name %s\n" % NAME)
    forms = [
        NAME,
        "/" + NAME,
        "command_service." + NAME,
        "command_service/" + NAME,
        "/command_service/" + NAME,
        "command_service.%s/CommandStream" % NAME,
        "/command_service.%s/CommandStream" % NAME,
        NAME.lower(),
        NAME.replace("_", ""),
        NAME.replace("CMD_", ""),
        "cmd_get_session_id",
        "GET_SESSION_ID",
    ]
    for f in forms:
        show("path=%r" % f, path=f)

    print("\nB. req payload shapes (packMode=JSON)")
    for p in ("", "{}", "null", "[]", '{"cmd":"%s"}' % NAME,
              json.dumps({"path": NAME}), "not json at all"):
        show("req=%r" % p[:28], path=NAME, payload=p)

    print("\nC. packMode")
    for pm in (0, 1, 2, 99):
        show("packMode=%d" % pm, path=NAME, pack_mode=pm)

    print("\nD. id variants")
    for rid in ("", "1", "test", str(uuid.uuid4()),
                "00000000-0000-0000-0000-000000000000"):
        show("id=%r" % rid[:24], path=NAME, req_id=rid)

    print("\nE. several commands at once on ONE stream")
    print("   (the rpc is bidirectional; the game may pipeline on a single call)")
    try:
        s = connect()
        import struct

        def fr(t, f, sid, body):
            return (len(body).to_bytes(3, "big") + bytes([t, f])
                    + (sid & 0x7FFFFFFF).to_bytes(4, "big") + body)

        for i, p in enumerate(["CMD_CONNECT_GRPC", "CMD_GET_SESSION_ID",
                               "CMD_LOGIN", "CMD_CREATE_USER"], start=1):
            m = command_request(str(uuid.uuid4()), p, "{}", 0)
            g = b"\x00" + len(m).to_bytes(4, "big") + m
            s.sendall(fr(0, 0x0, 1, g))       # END_STREAM clear: keep the stream
            print("   sent %s" % p)
        r = read_frames(s, 8.0, want_data=4)
        for _f, h in r["headers"]:
            if "grpc-status" in h:
                print("   -> grpc=%s %s" % (h["grpc-status"],
                                            unquote_plus(h.get("grpc-message", ""))[:50]))
        print("   total data bytes: %d" % len(r["data"]))
        s.close()
    except Exception as e:
        print("   ERROR %s: %s" % (type(e).__name__, e))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
