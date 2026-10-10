#!/usr/bin/env python3
"""squad_fix.py -- give the freshly minted bot a squad.

Proven by the 2026-10-01 capture: a new account has entry_info (23 players +
coach) but NO squad row (squad_list=[] -> GET_USER_SQUAD errors BVDL-).  The
real game bootstraps by pushing CMD_SET_MYCLUB_ENTRY_INFO; the captured
request is the template.

  payload      = captured owner sheet (base_team/check_status/squad_data/squad_name)
  base_team    <- bot's own entry_info.recommend_base_team_id
  coach        <- bot's entry_info.coach_list
  player_list  <- bot's entry_info.gameplayer_list (ids/serials are the bot's own)
  squad_gameplan / squad_name / check_status kept verbatim from the capture

Then verify with CMD_GET_USER_SQUAD.

  python squad_fix.py --live
"""
import json
import re
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import gate_client as gc  # noqa: E402
from room1 import (PACE, Gate, describe, load_capture,  # noqa: E402
                   next_rq, relay_quality)
from room2 import BOT_FILE, login_bot  # noqa: E402

CREATE_FILE = r"C:\Users\Administrator\Documents\Default Project\work\bot_create.json"
CAP = (r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
       r"\kgs-login\captures\2026-10-01-gate\gate-login-exchange.txt")
PAYLOAD_KEYS = ("base_team", "check_status", "squad_data", "squad_name")


def captured_set_request() -> dict:
    txt = open(CAP, encoding="utf-8", errors="replace").read()
    m = re.search(
        r"### REQ POST /pes22/gate/gate_CMD_SET_MYCLUB_ENTRY_INFO\.php"
        r".*?REQHEX: ([0-9a-f]+)", txt, re.S)
    return gc.decode(bytes.fromhex(m.group(1)))


def build_body(g, create_resp: dict) -> dict:
    cap = captured_set_request()
    payload = {k: cap[k] for k in PAYLOAD_KEYS if k in cap}
    ei = create_resp.get("entry_info") or {}

    payload["base_team"] = {
        "base_team_id": ei.get("recommend_base_team_id"),
        "base_team_license": "NOT_LICENSED",
        "team_name": "PLink Bot",
        "team_name_short": "PLB",
    }
    sd = payload["squad_data"]
    sd["coach"] = [{"coach_id": c["coach_id"]}
                   for c in ei.get("coach_list", [])]
    sd["player_list"] = [{"gameplayer_id": p["gameplayer_id"],
                          "uniform_number": p["uniform_number"]}
                         for p in ei.get("gameplayer_list", [])]

    m = g.envelope("CMD_SET_MYCLUB_ENTRY_INFO")
    m.update(payload)
    return m


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0

    reqs = load_capture()[0]
    with open(BOT_FILE, encoding="utf-8") as fh:
        bot = json.load(fh)
    with open(CREATE_FILE, encoding="utf-8") as fh:
        create = json.load(fh)

    same = ((create.get("pes_user_info") or {}).get("user_id") == bot.get("user_id"))
    print("identity match (create file vs bot file): %s" % same)
    if not same:
        print("stale files -- run mint.py first")
        return 1
    ei = create.get("entry_info") or {}
    print("roster: players=%d coach=%d recommend_base_team=%s"
          % (len(ei.get("gameplayer_list") or []),
             len(ei.get("coach_list") or []),
             ei.get("recommend_base_team_id")))

    botg = Gate()
    okb, rb = login_bot(botg, reqs, bot)
    print("bot login   -> %s" % (rb.get("result") if not okb else "NOERR"))
    if not okb:
        print("  %s" % describe(rb))
        return 1
    time.sleep(PACE)

    q = relay_quality(botg, reqs)
    print("bot quality -> %s" % q.get("result"))
    if q.get("result") != "NOERR":
        return 1
    time.sleep(PACE)

    body = build_body(botg, create)
    n = len(body["squad_data"]["player_list"])
    r1 = botg.send(body)
    print("set entry   -> %s  (pushed %d players) keys=%s"
          % (r1.get("result"), n, ",".join(sorted(r1))))
    if r1.get("result") != "NOERR":
        print("  %s" % describe(r1))
        return 1
    ei2 = r1.get("entry_info") or {}
    if isinstance(ei2, dict):
        print("  resp: main_squad_id=%s squad_list=%d gameplayers=%d"
              % (ei2.get("main_squad_id"), len(ei2.get("squad_list") or []),
                 len(ei2.get("gameplayer_list") or [])))
    time.sleep(PACE)

    m = botg.envelope("CMD_GET_USER_SQUAD")
    m["target_user_id"] = botg.uid
    r2 = botg.send(m)
    print("bot squad   -> %s" % r2.get("result"))
    if r2.get("result") != "NOERR":
        print("  %s" % describe(r2))
        return 1
    td = r2.get("team_data") or {}
    sd = r2.get("squad_data") or {}
    print("  team=%s  squad players=%d coach=%d"
          % (td.get("team_name"), len(sd.get("player_list") or []),
             len(sd.get("coach") or [])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
