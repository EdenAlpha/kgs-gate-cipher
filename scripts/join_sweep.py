#!/usr/bin/env python3
"""join_sweep.py -- recover the CMD_JOIN_ROOM input schema.

Method (ROOM-SCHEMA): probe at client_version 6.1.1, where input validation
runs BEFORE the session gate and cannot execute anything:
    GKZX- / ERR_INVALIDARG  = that variant's input is rejected
    ERR_INVALID_SESSION     = input ACCEPTED (only the cv-bound session gate
                              blocks execution)  -> winner
The winner body is then executed at 6.1.0 by the owner and by the bot.

Each variant differs from the baseline in exactly one field.

  python join_sweep.py            offline check
  python join_sweep.py --live     full run
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import (CFG, PACE, Gate, create_room, describe,  # noqa: E402
                   login, load_capture, next_rq, relay_quality)
from room2 import BOT_FILE, join_body, keys_of, login_bot  # noqa: E402

# The room must be the lobby 1v1 kind, and the join's mode must match it.
CFG["mode"] = "CUSTOM"
CFG["kind"] = "SINGLE"

DIAG_CV = "6.1.1"


def _id_str(m):
    m["room_id"] = {"id": str(m["room_id"]["id"])}


def _id_array(m):
    m["room_id"] = [str(m["room_id"]["id"])]


VARIANTS = [
    ("baseline", lambda m: None),
    ("mode=CUSTOM", lambda m: m.update(mode="CUSTOM")),
    ("mode=PRESET", lambda m: m.update(mode="PRESET")),
    ("id as string", _id_str),
    ("room_id array", _id_array),
    ("no user_compe_id", lambda m: m.pop("user_compe_id", None)),
    ("no strike_arena", lambda m: m.pop("strike_arena_selected_info", None)),
    ("is_invited=YES", lambda m: m.update(is_invited="YES")),
]


def build(g, rid, mutate=None, cv=None):
    m = join_body(g, rid, cv=cv)
    if mutate:
        mutate(m)
    return m


def main() -> int:
    live = "--live" in sys.argv
    reqs, resps = load_capture()
    try:
        with open(BOT_FILE, encoding="utf-8") as fh:
            bot = json.load(fh)
        bot_ok = bool(bot.get("user_id") and bot.get("auth_code"))
    except Exception:                                  # noqa: BLE001
        bot, bot_ok = {}, False
    print("capture: %d requests | bot identity: %s"
          % (len(reqs), "loaded" if bot_ok else "MISSING"))
    if not live:
        return 0 if bot_ok else 1

    t0 = time.time()
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

    winner = None
    for tag, mut in VARIANTS:
        d = owner.send(build(owner, rid, mutate=mut, cv=DIAG_CV))
        res = d.get("result")
        msg = d.get("msg") or ""
        extra = (" | " + msg[:160]) if msg else ""
        print("probe %-18s -> %s%s" % (tag, res, extra))
        time.sleep(PACE)
        if res == "ERR_INVALID_SESSION" or "session restart" in msg:
            winner = (tag, mut)
            print("  ^ input accepted (session gate reached)")
            break
        if res not in ("ERR_INVALIDARG",):
            print("  %s" % describe(d))
            winner = (tag, mut)
            break
    if not winner:
        print("no variant cleared input validation -- stopping")
        return 1
    print("winner: %s" % winner[0])
    tag, mut = winner

    jo = owner.send(build(owner, rid, mutate=mut))
    print("owner join   -> %s  keys=%s" % (jo.get("result"), keys_of(jo)))
    if jo.get("result") != "NOERR":
        print("  %s" % describe(jo))
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

    jb = botg.send(build(botg, rid, mutate=mut))
    print("bot join     -> %s  keys=%s" % (jb.get("result"), keys_of(jb)))
    if jb.get("result") != "NOERR":
        print("  %s" % describe(jb))
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 0 if jb.get("result") == "NOERR" else 1


if __name__ == "__main__":
    raise SystemExit(main())
