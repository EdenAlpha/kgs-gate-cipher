#!/usr/bin/env python3
"""Dump the full response for the paths that answered differently.

Six paths came back with no `grpc-status` header at all, which is not the same
as the `14 UNAVAILABLE` every other path produced. That could mean a real
`CommandResponse` in a DATA frame, or a different response shape entirely. This
prints every frame, the decoded headers, and the decoded `CommandResponse` so
the difference is visible rather than inferred.
"""
from __future__ import annotations

import os
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

ODD = ["/cmd_auth_google", "/v1/auth_google", "/api/auth_google",
       "/v1/error", "/v1/add_score", "/cmd_get_room_list", "/",
       "/cmd_login", "/v1/login"]


def show(path, payload="{}"):
    print("=" * 72)
    print("path = %r   req = %r" % (path, payload))
    try:
        r = call(path, payload, 0, str(uuid.uuid4()), settle=4.0)
    except Exception as e:
        print("   ERROR %s: %s" % (type(e).__name__, e))
        return
    print("   frames with headers: %d, data bytes: %d"
          % (len(r["headers"]), len(r["data"])))
    for flags, h in r["headers"]:
        print("   HEADERS (flags=%#04x):" % flags)
        for k, v in h.items():
            if k == "grpc-message":
                v = unquote_plus(v)
            print("      %-18s %s" % (k, v))
    d = r["data"]
    if not d:
        print("   (no DATA frame)")
        return
    print("   DATA raw: %s" % d.hex())
    if len(d) >= 5:
        comp = d[0]
        mlen = int.from_bytes(d[1:5], "big")
        body = d[5:5 + mlen]
        print("   gRPC: compressed=%d message_len=%d (body has %d bytes)"
              % (comp, mlen, len(body)))
        if len(body) >= 2 and body[0] == 0x0A:
            dec = command_response(body)
            print("   CommandResponse decoded:")
            for k, v in dec.items():
                print("      %-10s %r" % (k, v))
        else:
            print("   body is not a CommandResponse; first bytes: %s"
                  % body[:40].hex())
            try:
                print("   as text: %r" % body.decode("utf-8", "replace")[:200])
            except Exception:
                pass


def main() -> int:
    for p in ODD:
        show(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
