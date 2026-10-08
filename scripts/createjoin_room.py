#!/usr/bin/env python3
"""createjoin_room.py -- the working CMD_CREATEJOIN_ROOM flow.

Reproduces what the app does, in order:

  1. login                                  -> 6.1.0 session
  2. CMD_SET_GAMERELAY_QUALITY              -> ping rows written first
  3. CMD_CREATEJOIN_ROOM                    -> room_id

Two findings make this work and are easy to get wrong:

  * step 2 must use the CAPTURED 46 region names, not the regions
    returned by CMD_GET_GAMERELAY_QUALITYCHECK_LIST (which now returns a
    different set of 63 ping targets). The new list validates at 6.1.1
    and still fails the insert at 6.1.0 with ERR_DATABASE.

  * strike_arena_selected_info must be present, as a list of maps with
    player_id and costume_id BOTH as ints. Omitting it passes validation
    and then fails at the database.

rqid must increment per request: the gate caches responses on rqid.

STATE-CHANGING: creates a room on the live server.
"""

import json
import re
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\AppData\Local\Temp\2")
from gate_client import s_keyword          # noqa: E402
from probe50 import BASE, post, ua         # noqa: E402
from probe65 import login                  # noqa: E402

CAPTURE = r"C:\Users\Administrator\AppData\Local\Temp\2\gate_decoded.txt"
CV = "6.1.0"

CS_KEYS = ["mode", "event_id", "kind", "name_tag", "entry_restriction",
           "password", "lang", "capacity", "observer_capacity",
           "guest_num_by_user", "is_coop_vs_com_single"]
ME_KEYS = ["condition_home", "condition_away", "cpu_level", "match_time",
           "injury", "ball_type", "exTime", "pk", "substitution_times",
           "substitution", "exSubstitution", "limitTime", "equalization",
           "regulation", "can_use_mobile_controller"]
NET_KEYS = ["host_address", "host_port", "reflexive_address",
            "reflexive_port", "nat_type"]

CFG = {"mode": "STRIKE_ARENA", "event_id": 0, "kind": "STRIKE_ARENA",
       "name_tag": 0, "entry_restriction": "NONE", "password": "",
       "lang": "US", "capacity": 2, "observer_capacity": 0,
       "guest_num_by_user": 0, "is_coop_vs_com_single": "NO",
       "condition_home": "CONDITION_RANDOM",
       "condition_away": "CONDITION_RANDOM", "cpu_level": "EASY",
       "match_time": 1, "injury": "NO", "ball_type": 1, "exTime": "0",
       "pk": "NO", "substitution_times": 1, "substitution": 1,
       "exSubstitution": "", "limitTime": "NOSET", "equalization": "NO",
       "regulation": "", "can_use_mobile_controller": "NO",
       "event_account_type": "GAME_PLAYER", "psid": "", "xbsid": "",
       "a4.host_address": "", "a4.host_port": 1,
       "a4.reflexive_address": "", "a4.reflexive_port": 1,
       "a4.nat_type": 1, "a6.host_address": "", "a6.host_port": 1,
       "a6.reflexive_address": "", "a6.reflexive_port": 1,
       "a6.nat_type": 1}

_rqid = [1200000]


def envelope(msgid, sid, uid, cv=CV):
    _rqid[0] += 1
    m = dict(BASE)
    m.update({"msgid": msgid, "user_id": uid, "session_id": sid,
              "client_version": cv, "s_keyword": s_keyword(cv),
              "rqid": _rqid[0]})
    return m


def set_relay_quality(sid, uid):
    txt = open(CAPTURE, encoding="utf-8", errors="replace").read()
    pat = re.compile(
        r"^REQ\s+\S*gate_CMD_SET_GAMERELAY_QUALITY\.php\s+wire=\d+\s"
        r"+plain=\d+\s+\S+\s+msgpack=\d+\s*\n(.*?)(?=^REQ\s|^RESP\s|^====)",
        re.S | re.M)
    cap = json.loads(pat.search(txt).group(1))
    ql = [dict(e, last_update=int(time.time()))
          for e in cap["quality_list"]]
    m = envelope("CMD_SET_GAMERELAY_QUALITY", sid, uid)
    m["quality_list"] = ql
    return post(m, ua(cv=CV))


def create_room(sid, uid):
    m = envelope("CMD_CREATEJOIN_ROOM", sid, uid)
    m["core_settings"] = {k: CFG[k] for k in CS_KEYS}
    m["match_settings"] = {"match_env": {k: CFG[k] for k in ME_KEYS}}
    m["event_account_type"] = CFG["event_account_type"]
    m["address_ipv4"] = {k: CFG["a4." + k] for k in NET_KEYS}
    m["address_ipv6"] = {k: CFG["a6." + k] for k in NET_KEYS}
    m["platform_session_id_info"] = {"ps_session_id": CFG["psid"],
                                     "xb_session_id": CFG["xbsid"]}
    m["strike_arena_selected_info"] = [{"player_id": 1, "costume_id": 0}]
    return post(m, ua(cv=CV))


def main():
    print("=== create room @ %s ===" % time.strftime("%H:%M:%S"))
    sid, uid = login()
    if not sid:
        return 1
    print("   session ok, user_id=%s" % uid)

    q = set_relay_quality(sid, uid)
    print("   SET_GAMERELAY_QUALITY -> %s" % q.get("result"))
    if q.get("result") != "NOERR":
        return 1

    o = create_room(sid, uid)
    print("   CMD_CREATEJOIN_ROOM    -> %s" % o.get("result"))
    print("   %s" % json.dumps(o, ensure_ascii=False, default=str))
    if o.get("result") == "NOERR":
        print("\n   ROOM NUMBER: %r" % (o.get("room_id"),))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
