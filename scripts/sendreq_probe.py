#!/usr/bin/env python3
"""sendreq_probe.py -- recover the real join ladder around CMD_JOIN_ROOM.

CMD_JOIN_ROOM alone gives NQZT- for both sides.  The binary shows two more
commands on the join path:

  CMD_SEND_JOIN_ROOM_REQUEST   {target_user_id:int32, room_id:{id:int64}}
  CMD_GET_REQUESTED_JOIN_ROOM_INFO {sender_user_id:int32}
      -> requested_join_room_info

Ladder (owner creates the room, bot tries to get seated):
  3  bot   SEND_JOIN_ROOM_REQUEST {target: 0, room}
  4  owner GET_ROOM_INFO -> num_users
  5  owner SEND_JOIN_ROOM_REQUEST {target: bot, room}   (invite direction)
  6  bot   GET_REQUESTED_JOIN_ROOM_INFO {sender: owner}
  7  owner GET_REQUESTED_JOIN_ROOM_INFO {sender: bot}
  8  bot   JOIN_ROOM (mode CUSTOM)
  9  owner GET_ROOM_INFO -> num_users

  python sendreq_probe.py --live
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import (CFG, PACE, Gate, create_room, describe,  # noqa: E402
                   login, load_capture, next_rq, relay_quality)
from room2 import BOT_FILE, join_body, keys_of, login_bot  # noqa: E402
from room_info_shape import shape  # noqa: E402

CFG["mode"] = "CUSTOM"
CFG["kind"] = "SINGLE"


def sendreq(g: Gate, target: int, rid: int) -> dict:
    m = g.envelope("CMD_SEND_JOIN_ROOM_REQUEST")
    m["target_user_id"] = target
    m["room_id"] = {"id": rid}
    return g.send(m)


def getrequested(g: Gate, sender: int) -> dict:
    m = g.envelope("CMD_GET_REQUESTED_JOIN_ROOM_INFO")
    m["sender_user_id"] = sender
    return g.send(m)


def num_users(g: Gate, rid: int) -> object:
    m = g.envelope("CMD_GET_ROOM_INFO")
    m.update({"mode": "CUSTOM", "id": 0, "room_id": {"id": rid},
              "event_id": 0, "user_compe_id": 0, "is_room_search": "NO"})
    r = g.send(m)
    info = r.get("room_info")
    if isinstance(info, dict):
        return info.get("num_users")
    return "err:%s" % r.get("result")


def main() -> int:
    if "--live" not in sys.argv:
        print("use --live")
        return 1
    t0 = time.time()
    reqs = load_capture()[0]
    try:
        with open(BOT_FILE, encoding="utf-8") as fh:
            bot = json.load(fh)
    except Exception:                                  # noqa: BLE001
        bot = {}
    if not (bot.get("user_id") and bot.get("auth_code")):
        print("bot identity MISSING (run mint.py)")
        return 1

    owner = Gate()
    ok, r = login(owner, reqs)
    print("owner login  -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    time.sleep(PACE)
    q = relay_quality(owner, reqs)
    print("owner quality-> %s" % q.get("result"))
    if q.get("result") != "NOERR":
        return 1
    time.sleep(PACE)
    o = create_room(owner)
    rid = ((o.get("room_id") or {}).get("id")) if o.get("result") == "NOERR" else None
    print("create room  -> %s  room_id=%s" % (o.get("result"), rid))
    if not rid:
        print("  %s" % describe(o))
        return 1
    time.sleep(PACE)

    botg = Gate()
    okb, rb = login_bot(botg, reqs, bot)
    print("bot login    -> %s" % (rb.get("result") if not okb else "NOERR"))
    if not okb:
        print("  %s" % describe(rb))
        return 1
    time.sleep(PACE)
    qb = relay_quality(botg, reqs)
    print("bot quality  -> %s" % qb.get("result"))
    if qb.get("result") != "NOERR":
        return 1
    time.sleep(PACE)

    n0 = num_users(owner, rid)
    print("seated       -> %s (owner only)" % n0)
    time.sleep(PACE)

    a = sendreq(botg, 0, rid)
    print("bot sendreq  -> %s keys=%s" % (a.get("result"), keys_of(a)))
    if a.get("result") != "NOERR":
        print("  %s" % describe(a))
    else:
        extra = {k: v for k, v in a.items()
                 if k not in ("result", "msgid", "rqid", "errcode",
                              "show_info", "maintenance_end_time")}
        if extra:
            print("  %s" % json.dumps(shape(extra), ensure_ascii=False,
                                      default=str))
    time.sleep(PACE)

    n1 = num_users(owner, rid)
    print("seated       -> %s" % n1)
    time.sleep(PACE)

    if n1 != 2:
        b = sendreq(owner, botg.uid, rid)
        print("owner invite -> %s keys=%s" % (b.get("result"), keys_of(b)))
        if b.get("result") != "NOERR":
            print("  %s" % describe(b))
        time.sleep(PACE)

    c = getrequested(botg, owner.uid)
    print("bot getreq   -> %s keys=%s" % (c.get("result"), keys_of(c)))
    if c.get("result") != "NOERR":
        print("  %s" % describe(c))
    elif c.get("requested_join_room_info") is not None:
        print("  %s" % json.dumps(shape(c.get("requested_join_room_info")),
                                  ensure_ascii=False, default=str))
    time.sleep(PACE)

    d = getrequested(owner, botg.uid)
    print("owner getreq -> %s keys=%s" % (d.get("result"), keys_of(d)))
    if d.get("result") != "NOERR":
        print("  %s" % describe(d))
    elif d.get("requested_join_room_info") is not None:
        print("  %s" % json.dumps(shape(d.get("requested_join_room_info")),
                                  ensure_ascii=False, default=str))
    time.sleep(PACE)

    j = join_body(botg, rid)
    j["mode"] = "CUSTOM"
    e = botg.send(j)
    print("bot join     -> %s keys=%s" % (e.get("result"), keys_of(e)))
    if e.get("result") != "NOERR":
        print("  %s" % describe(e))
    time.sleep(PACE)

    n2 = num_users(owner, rid)
    print("seated       -> %s  (final)" % n2)
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 0 if n2 == 2 else 1


if __name__ == "__main__":
    raise SystemExit(main())
