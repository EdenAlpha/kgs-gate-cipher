#!/usr/bin/env python3
"""Is `path` a number, an empty string, or something else entirely?

Every `CMD_*` name, every qualification of one, and every payload shape returns
`grpc-status: 14 UNAVAILABLE`. The remaining possibilities for a `string` field
are worth ruling out cheaply:

  * a numeric command id, as a decimal string;
  * the empty string (a "default" route);
  * a single character or a very short token;
  * a URL path in the same style as the game's plain-HTTP endpoints, which use
    `http://ntl.service.konami.net/ntl/api/GateInfo.php`.

Any path that does not return 14 is printed in full. A response with a DATA
frame would mean the command resolved and we would finally see a
`CommandResponse`.
"""
from __future__ import annotations

import os
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402


def probe(path, payload="{}"):
    try:
        r = call(path, payload, 0, str(uuid.uuid4()), settle=3.0)
    except Exception as e:
        return "ERR", "%s: %s" % (type(e).__name__, e), b""
    st, gm = "-", ""
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = unquote_plus(h.get("grpc-message", ""))
    return st, gm, r["data"]


def main() -> int:
    groups = {
        "numeric ids": ["0", "1", "2", "3", "10", "100", "1000", "1001",
                        "10000", "99999", "-1"],
        "empty / short": ["", " ", "/", ".", "a", "0.0", "null", "none",
                          "default", "root"],
        "url-style, like the game's http endpoints": [
            "/ntl/api/GateInfo.php", "ntl/api/GateInfo.php",
            "/api/GateInfo.php", "/ntl/api/", "/api/",
            "http://ntl.service.konami.net/ntl/api/GateInfo.php",
            "https://ntl.service.konami.net/ntl/api/GateInfo.php",
        ],
        "grpc method paths": [
            "/command_service.CommandService/CommandStream",
            "command_service.CommandService/CommandStream",
            "/command_service.CommandService/GetSessionId",
            "/command_service.CommandService/Login",
        ],
        "versioned api paths": [
            "/v1/session", "/v1/login", "/api/v1/session", "/api/session",
            "/session", "/login", "/auth", "/connect", "/grpc",
            "/kgs/session", "/gate", "/command",
        ],
    }
    hits = []
    for title, items in groups.items():
        print("== %s" % title)
        for p in items:
            st, gm, data = probe(p)
            mark = ""
            if st not in ("14", "ERR"):
                mark = "   <<<<<< NOT 14"
                hits.append((p, st, gm, data))
            print("   %-52r -> %-4s %s%s"
                  % (p[:50], st, gm[:44], mark))
    print("\nnon-14 responses: %d" % len(hits))
    for p, st, gm, data in hits:
        print("  %r grpc=%s %s" % (p, st, gm))
        if len(data) >= 5:
            mlen = int.from_bytes(data[1:5], "big")
            print("    CommandResponse: %s" % command_response(data[5:5 + mlen]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
