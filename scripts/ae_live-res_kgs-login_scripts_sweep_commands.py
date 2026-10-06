#!/usr/bin/env python3
"""Find which `path` values the server actually resolves.

The schema is now correct, so every request parses; the application answers
`grpc-status: 14 UNAVAILABLE` for a command name it does not know. That makes
the server a clean membership test: any path that does NOT return 14 is a real
command.

The candidate names come from the 384 `CMD_*` strings in libUE4.so, tried in an
order that starts with the ones that plausibly come first in a session.
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, PACK_JSON, PACK_MSGPACK  # noqa: E402
from urllib.parse import unquote_plus  # noqa: E402

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"

PRIORITY = [
    "CMD_CONNECT_GRPC", "CMD_GET_SESSION_ID", "CMD_CONNECT", "CMD_HELLO",
    "CMD_CREATE_USER", "CMD_AUTH_XSTS", "CMD_AUTH_GOOGLE", "CMD_LOGIN",
    "CMD_GET_USER_INFO", "CMD_CHECK_MATCH_ENABLE", "CMD_CREATEJOIN_ROOM",
    "CMD_GET_ROOM_INFO", "CMD_SEND_RECRUIT_CODE", "CMD_ERROR",
    "CMD_END_CONNECTION", "CMD_FAILED_COUNT_GRPC", "CMD_FINISHED_COUNT_GRPC",
]


def status_of(r):
    st, gm = "-", ""
    for _flags, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = unquote_plus(h.get("grpc-message", ""))
    return st, gm, len(r["data"])


def main() -> int:
    d = open(SO, "rb").read()
    names = sorted(set(m.group(0).decode()
                       for m in re.finditer(rb"CMD_[A-Z0-9_]{2,48}", d)))
    print("%d CMD_* names in the binary\n" % len(names))

    tried = []
    hits = []
    print("A. priority names")
    for p in PRIORITY:
        if p not in names:
            print("  %-30s (not in binary)" % p)
            continue
        r = call(p, "{}", PACK_JSON)
        st, gm, dl = status_of(r)
        tried.append(p)
        mark = "" if st == "14" else "   <<<<<< RESOLVED"
        print("  %-30s -> grpc=%-4s data=%-4d %s%s"
              % (p, st, dl, gm[:50], mark))
        if st != "14":
            hits.append((p, st, gm, r))

    print("\nB. sweeping the remaining %d names" % (len(names) - len(tried)))
    n = 0
    for p in names:
        if p in tried:
            continue
        n += 1
        try:
            r = call(p, "{}", PACK_JSON)
        except Exception as e:
            print("  %-30s ERROR %s" % (p, e))
            continue
        st, gm, dl = status_of(r)
        if st != "14":
            print("  %-30s -> grpc=%-4s data=%-4d %s   <<<<<< RESOLVED"
                  % (p, st, dl, gm[:60]))
            hits.append((p, st, gm, r))
        if n % 25 == 0:
            print("     ...%d/%d swept, %d resolved" % (n, len(names) - len(tried),
                                                        len(hits)))
    print("\nswept %d, resolved %d" % (n, len(hits)))
    if hits:
        print("\n=== RESOLVED COMMANDS ===")
        for p, st, gm, r in hits:
            print("  %-32s grpc=%-4s %s" % (p, st, gm[:80]))
            if r["data"]:
                print("      data: %s" % r["data"][:80].hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
