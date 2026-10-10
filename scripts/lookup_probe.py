#!/usr/bin/env python3
"""lookup_probe.py -- what identifier does the server really index rooms by?

Reads only (plus one create): after creating a CUSTOM/SINGLE room,
  1. CMD_GET_ROOM_LIST with the create id as the search number
     -> if room_info comes back, the element shows the room's real id FORM
  2. CMD_GET_ROOM_INFO with array and map forms
  3. last step: one CMD_JOIN_ROOM execution with room_id.id as STRING

  python lookup_probe.py --live
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import (CFG, PACE, Gate, create_room, describe,  # noqa: E402
                   login, load_capture, next_rq, relay_quality)
from room2 import join_body, keys_of  # noqa: E402

CFG["mode"] = "CUSTOM"
CFG["kind"] = "SINGLE"


def brief(o):
    """result + top-level keys; room_info summarized, members never printed."""
    out = {"result": o.get("result"), "errcode": o.get("errcode"),
           "keys": sorted(o) if isinstance(o, dict) else None}
    ri = o.get("room_info")
    if isinstance(ri, list):
        out["room_info_len"] = len(ri)
        if ri and isinstance(ri[0], dict):
            out["room_elem_keys"] = sorted(ri[0])
            out["room_elem_id"] = ri[0].get("id")
            out["room_elem_room_id"] = ri[0].get("room_id")
    if o.get("msg"):
        out["msg"] = str(o["msg"])[:200]
    return json.dumps(out, ensure_ascii=False, default=str)


def main() -> int:
    if "--live" not in sys.argv:
        reqs, _ = load_capture()
        print("capture: %d requests" % len(reqs))
        return 0

    t0 = time.time()
    g = Gate()
    ok, r = login(g, reqs := load_capture()[0])
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

    # 1. room list, the create id used as the typed search number
    m = g.envelope("CMD_GET_ROOM_LIST")
    m.update({"start_index": 0, "num": 10, "kind": "SINGLE",
              "mode": "ROOM_VACANCY_AND_WAITING", "platform": "ANDROID",
              "cross_platform_option": "YES",
              "filter_settings": {"room_id": [str(rid)]},
              "is_room_search": "NO"})
    r1 = g.send(m)
    print("room_list    -> %s" % brief(r1))
    time.sleep(PACE)

    # 2. room info, two id forms
    for tag, val in (("array-str", [str(rid)]), ("map-int", {"id": rid})):
        m = g.envelope("CMD_GET_ROOM_INFO")
        m.update({"mode": "CUSTOM", "id": 0, "room_id": val,
                  "event_id": 0, "user_compe_id": 0, "is_room_search": "NO"})
        ri = g.send(m)
        print("room_info[%s] -> %s" % (tag, brief(ri)))
        time.sleep(PACE)

    # 3. one join execution: room_id.id as STRING
    jm = join_body(g, rid)
    jm["room_id"] = {"id": str(rid)}
    jj = g.send(jm)
    print("join[id str] -> %s  keys=%s" % (jj.get("result"), keys_of(jj)))
    if jj.get("result") != "NOERR":
        print("  %s" % describe(jj))
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
