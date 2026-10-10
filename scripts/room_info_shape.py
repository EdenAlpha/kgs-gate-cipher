#!/usr/bin/env python3
"""room_info_shape.py -- create a room, read it back, print the STRUCTURE
of CMD_GET_ROOM_INFO's room_info (keys and types; identity values masked).
That is the server's own idea of a room -- compare it against CMD_JOIN_ROOM.

  python room_info_shape.py --live
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import (CFG, PACE, Gate, create_room, describe,  # noqa: E402
                   login, load_capture, next_rq, relay_quality)

CFG["mode"] = "CUSTOM"
CFG["kind"] = "SINGLE"

SENSITIVE = {"user_id", "session_id", "auth_code", "user_name", "password",
             "sender_user_id", "member_user_id", "id_list", "target_user_id"}


def shape(v, key=None, depth=0):
    if isinstance(v, dict):
        if depth > 6:
            return "{...}"
        return {k: shape(x, k, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        out = [shape(x, key, depth + 1) for x in v[:2]]
        if len(v) > 2:
            out.append("...(%d)" % len(v))
        return out
    if key in SENSITIVE:
        return "<redacted:%s>" % type(v).__name__
    if isinstance(v, str) and len(v) > 40:
        return "<str:%d>" % len(v)
    return v


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check only in this script; use --live")
        return 0
    t0 = time.time()
    reqs = load_capture()[0]
    g = Gate()
    ok, r = login(g, reqs)
    print("owner login  -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    time.sleep(PACE)
    q = relay_quality(g, reqs)
    print("owner quality-> %s" % q.get("result"))
    if q.get("result") != "NOERR":
        return 1
    time.sleep(PACE)
    o = create_room(g)
    rid = ((o.get("room_id") or {}).get("id")) if o.get("result") == "NOERR" else None
    print("create room  -> %s  room_id=%s" % (o.get("result"), rid))
    if not rid:
        print("  %s" % describe(o))
        return 1
    time.sleep(PACE)

    m = g.envelope("CMD_GET_ROOM_INFO")
    m.update({"mode": "CUSTOM", "id": 0, "room_id": {"id": rid},
              "event_id": 0, "user_compe_id": 0, "is_room_search": "NO"})
    ri = g.send(m)
    print("room_info    -> %s" % ri.get("result"))
    info = ri.get("room_info")
    print(json.dumps(shape(info), indent=1, ensure_ascii=False, default=str))
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
