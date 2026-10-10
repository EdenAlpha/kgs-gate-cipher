#!/usr/bin/env python3
"""squad_probe.py -- what squad/entry state does each account really have?

Account-level reads only (no room flow):
  bot   CMD_GET_MYCLUB_ENTRY_INFO   envelope-only request -> entry_info
  owner CMD_GET_MYCLUB_ENTRY_INFO   the SET body reference
  bot   CMD_GET_USER_SQUAD          (known BVDL-) -- re-read after entry_info
                                     in case the read bootstraps a default squad

  python squad_probe.py --live
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

from room1 import (PACE, Gate, describe, login,  # noqa: E402
                   load_capture, next_rq, relay_quality)
from room2 import BOT_FILE, login_bot  # noqa: E402
from room_info_shape import SENSITIVE, shape  # noqa: E402

SENSITIVE.update({"id", "serial"})


def show(o) -> str:
    return json.dumps(shape(o), ensure_ascii=False, default=str)


def warehouse(g: Gate) -> dict:
    return g.send(g.envelope("CMD_GET_MYCLUB_WAREHOUSE_PLAYERLIST"))


def user_squad(g: Gate, target: int) -> dict:
    m = g.envelope("CMD_GET_USER_SQUAD")
    m["target_user_id"] = target
    return g.send(m)


def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0
    t0 = time.time()
    reqs = load_capture()[0]
    with open(BOT_FILE, encoding="utf-8") as fh:
        bot = json.load(fh)

    owner = Gate()
    ok, r = login(owner, reqs)
    print("owner login  -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    time.sleep(PACE)
    botg = Gate()
    okb, rb = login_bot(botg, reqs, bot)
    print("bot login    -> %s" % (rb.get("result") if not okb else "NOERR"))
    if not okb:
        print("  %s" % describe(rb))
        return 1
    time.sleep(PACE)

    for who, g in (("owner", owner), ("bot  ", botg)):
        ei = warehouse(g)
        print("warehouse [%s] -> %s warehouse_num=%s keys=%s"
              % (who, ei.get("result"), ei.get("warehouse_num"),
                 ",".join(sorted(ei))))
        gl = ei.get("gameplayer_list")
        if isinstance(gl, list):
            print("  len=%d  %s" % (len(gl), show(gl[:2])))
        elif ei.get("result") != "NOERR":
            print("  %s" % describe(ei))
        time.sleep(PACE)

    sq = user_squad(botg, botg.uid)
    print("bot squad2   -> %s" % sq.get("result"))
    if sq.get("result") == "NOERR":
        print("  %s" % show({k: sq[k] for k in ("team_data",) if k in sq}))
    else:
        print("  %s" % describe(sq))
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
