#!/usr/bin/env python3
"""Which field names do the room commands put in their bodies?

The ctor's serialiser only writes the 10-field base map (msgid, rqid, user_id,
session_id, my_platform, s_keyword, lang, region, platform, client_version).
The per-command writer (like CMD_LOGIN's 0x76b1b28) appends the real fields.
Find those field names so we can build correct bodies.

    python find_room_fields.py room|recruit|session|login
"""
from __future__ import annotations

import re
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

GROUPS = {
    "room": re.compile(rb"\b(room_[a-z_]{2,20}|max_(?:user|num|entry)[a-z_]*|"
                      rb"(?:entry|recruit|pass[a-z]*)_?(?:code|num|id)|"
                      rb"match_(?:mode|kind|type|num)|comment|team_(?:id|num)|"
                      rb"select_[a-z_]{2,16}|game_(?:mode|kind)|"
                      rb"entry_(?:num|id|code))\x00"),
    "recruit": re.compile(rb"\b(recruit[a-z_]{0,20}|code[a-z_]{0,12})\x00"),
    "session": re.compile(rb"\b(session[a-z_]{0,20}|token[a-z_]{0,12})\x00"),
    "login": re.compile(rb"\b(auth_[a-z_]{2,20}|hash[a-z_]{0,12}|"
                        rb"kgs[a-z_]{0,20}|guest[a-z_]{0,20})\x00"),
}


def main() -> int:
    want = sys.argv[1] if len(sys.argv) > 1 else "room"
    pat = GROUPS.get(want, GROUPS["room"])
    d = open(SO, "rb").read()
    seen = set()
    for m in pat.finditer(d):
        s = m.group()[:-1].decode("latin1")
        if s in seen:
            continue
        seen.add(s)
        ctx = d[m.start():m.end() + 24]
        print("  %-28s va=%#x  %r" % (s, m.start(), ctx[:60]))
    print("total:", len(seen))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
