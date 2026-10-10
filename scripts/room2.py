#!/usr/bin/env python3
"""room2.py -- two-sided run: owner creates a lobby 1v1 room, bot joins it.

  python room2.py            offline self-test (no network)
  python room2.py --live     full run

Flow:
  1  owner login            (capture identity, credential-free)
  2  relay quality          (captured 46 regions)
  3  create CUSTOM/SINGLE   -> room_id
  4  JOIN schema probe @6.1.1 (verbose validator; cannot execute)
  5  owner self-join  @6.1.0
  6  bot login + relay quality   (identity from bot_identity.json)
  7  bot join         @6.1.0

The join body comes from the CMD_JOIN_ROOM request builder recovered from
libUE4.so (func 0x77c5a14): mode, room_id{id}, event_id, password,
is_need_password, address_ipv4/ipv6, platform_session_id_info,
event_account_type, is_invited, strike_arena_selected_info, user_compe_id.
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import gate_client as gc  # noqa: E402
from room1 import (CFG, BUILD, CV, PACE, Gate, create_room, describe,  # noqa: E402
                   login, load_capture, next_rq, relay_quality)

BOT_FILE = r"C:\Users\Administrator\Documents\Default Project\work\bot_identity.json"
DIAG_CV = "6.1.1"
NET = {"host_address": "", "host_port": 1, "reflexive_address": "",
       "reflexive_port": 1, "nat_type": 1}


def login_bot(g: Gate, reqs, bot) -> tuple[bool, dict]:
    m = dict(gc.decode(reqs["CMD_LOGIN"]))
    m["rqid"] = next_rq()
    m["user_id"] = bot["user_id"]
    m["auth_code"] = bot["auth_code"]
    m["session_id"] = ""
    m["hash"] = gc.decode(reqs["CMD_CREATE_USER"]).get("hash") or m.get("hash")
    m["client_version"] = CV
    m["s_keyword"] = gc.s_keyword(CV, BUILD)
    r = g.send(m)
    if r.get("result") == "NOERR" and r.get("session_id"):
        g.sid = r["session_id"]
        g.uid = bot["user_id"]
        g.base = {k: m[k] for k in ("my_platform", "lang", "region",
                                    "platform") if k in m}
        return True, r
    return False, r


def join_body(g: Gate, room_id: int, cv: str | None = None) -> dict:
    m = g.envelope("CMD_JOIN_ROOM")
    if cv and cv != CV:
        m["client_version"] = cv
        m["s_keyword"] = gc.s_keyword(cv, BUILD)
    m["mode"] = "GAME_PLAYER"
    m["room_id"] = {"id": room_id}
    m["event_id"] = 0
    m["password"] = ""
    m["is_need_password"] = "NO"
    m["address_ipv4"] = dict(NET)
    m["address_ipv6"] = dict(NET)
    m["platform_session_id_info"] = {"ps_session_id": "", "xb_session_id": ""}
    m["event_account_type"] = "GAME_PLAYER"
    m["is_invited"] = "NO"
    m["strike_arena_selected_info"] = [{"player_id": 1, "costume_id": 0}]
    m["user_compe_id"] = 0
    return m


def keys_of(o) -> str:
    return ",".join(sorted(o)) if isinstance(o, dict) else "?"


def main() -> int:
    live = "--live" in sys.argv
    for arg in sys.argv[1:]:
        if arg.startswith("--mode="):
            CFG["mode"] = arg.split("=", 1)[1]
        if arg.startswith("--kind="):
            CFG["kind"] = arg.split("=", 1)[1]
    CFG.setdefault("mode", "CUSTOM")
    if "--live" not in sys.argv and not any(a.startswith("--mode=")
                                            for a in sys.argv):
        CFG["mode"] = "CUSTOM"
    if "--live" not in sys.argv and not any(a.startswith("--kind=")
                                            for a in sys.argv):
        CFG["kind"] = "SINGLE"

    reqs, resps = load_capture()
    bot_ok = False
    try:
        with open(BOT_FILE, encoding="utf-8") as fh:
            bot = json.load(fh)
        bot_ok = bool(bot.get("user_id") and bot.get("auth_code"))
    except Exception:                                  # noqa: BLE001
        bot = {}
    print("capture: %d requests | bot identity: %s"
          % (len(reqs), "loaded" if bot_ok else "MISSING (run mint.py)"))
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

    # -- schema probe at 6.1.1: verbose input errors, cannot execute ------
    d = owner.send(join_body(owner, rid, cv=DIAG_CV))
    msg = d.get("msg") or ""
    verdict = "unknown"
    if "input error" in msg:
        verdict = "SCHEMA-INVALID"
    elif d.get("result") == "ERR_INVALID_SESSION" or "session restart" in msg:
        verdict = "schema-ok"
    print("join probe   -> %s  [%s]" % (d.get("result"), verdict))
    if verdict == "SCHEMA-INVALID":
        print("  %s" % describe(d))
        return 1
    time.sleep(PACE)

    j = owner.send(join_body(owner, rid))
    print("owner join   -> %s  keys=%s" % (j.get("result"), keys_of(j)))
    if j.get("result") != "NOERR":
        print("  %s" % describe(j))
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

    jb = botg.send(join_body(botg, rid))
    print("bot join     -> %s  keys=%s" % (jb.get("result"), keys_of(jb)))
    if jb.get("result") != "NOERR":
        print("  %s" % describe(jb))
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 0 if jb.get("result") == "NOERR" else 1


if __name__ == "__main__":
    raise SystemExit(main())
