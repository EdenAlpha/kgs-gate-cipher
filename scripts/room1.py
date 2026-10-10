#!/usr/bin/env python3
"""room1.py -- rebuilt live chain runner: login -> relay quality -> create room.

Credential-free by construction: the login credentials are decoded from the
COMMITTED ciphertext capture (gate-login-exchange.txt) at runtime and never
written to disk, so this script is safe to commit.

Rebuild of the wiped Temp\2 flow (probe65.login + probe50.post +
createjoin_room.py); all three references survive in kgs-gate-cipher.

  python room1.py            offline decode-only self-test (no network)
  python room1.py --live     login + create room on the live server

The gate caches responses on rqid, so rqid starts fresh high and increments
per request.  Pacing ~0.4 s to avoid ERR_CONGESTION (JPFJ-).
"""
from __future__ import annotations

import json
import random
import re
import sys
import time

ROOT = r"C:\Users\Administrator\Documents\Default Project"
sys.path.insert(0, ROOT + r"\kgs-gate-cipher")
import gate_client as gc  # noqa: E402

CAPTURE = (ROOT + r"\peerlink-efootball-disconnects\kgs-login\captures"
           r"\2026-10-01-gate\gate-login-exchange.txt")
CV = "6.1.0"
BUILD = "11.1.0"
RQID0 = 1500000
PACE = 0.4
# Random per-process base: the gate caches responses on rqid, and a fixed
# starting value makes a second process replay the first one's responses
# (observed: two runs answered with the identical room_id).
_RQ = [RQID0 + random.randint(0, 4_000_000)]


def next_rq() -> int:
    """Process-wide rqid.  The gate caches responses on rqid, so every
    request -- from either identity -- must get a fresh one."""
    _RQ[0] += 1
    return _RQ[0]

# ---- working CFG, verbatim from scripts/createjoin_room.py --------------
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


def load_capture(path: str = CAPTURE):
    """Parse the committed gate exchange -> {CMD: req_bytes}, {CMD: resp_bytes}."""
    txt = open(path, encoding="utf-8", errors="replace").read()
    txt = txt.replace("\r\n", "\n")
    reqs, resps = {}, {}
    for block in re.split(r"(?=^### )", txt, flags=re.M):
        mh = re.match(r"### (REQ|RESP) POST /pes22/gate/gate_(\w+)\.php", block)
        if not mh:
            continue
        me = re.search(r"^(?:REQ|RESP)HEX: ([0-9a-f]+)\s*$", block, flags=re.M)
        if not me:
            continue
        target = reqs if mh.group(1) == "REQ" else resps
        target.setdefault(mh.group(2), bytes.fromhex(me.group(1)))
    return reqs, resps


class Gate:
    def __init__(self):
        self.rqid = RQID0
        self.sid = ""
        self.uid = 0
        self.base = {}
        gc.UA = gc.ua(client_version=CV)   # dynamic UA, headers_for reads it

    def envelope(self, msgid: str) -> dict:
        self.rqid = next_rq()
        return {
            "msgid": msgid,
            "rqid": self.rqid,
            "user_id": self.uid,
            "session_id": self.sid,
            "my_platform": self.base.get("my_platform", "ANDROID"),
            "s_keyword": gc.s_keyword(CV, BUILD),
            "lang": self.base.get("lang", "US"),
            "region": self.base.get("region", "REGION_US"),
            "platform": self.base.get("platform", "ANDROID"),
            "client_version": CV,
        }

    def send(self, msg: dict, timeout: int = 25) -> dict:
        body = gc.encode(msg)
        sign = gc.make_sign(body)
        status, hdrs, data = gc.post(msg["msgid"], body, sign, timeout)
        if not data:
            return {"result": "_HTTP_EMPTY", "_status": status}
        try:
            out = gc.decode(data)
        except Exception as exc:                     # noqa: BLE001
            return {"result": "_DECODE_FAIL", "_err": str(exc),
                    "_status": status, "_len": len(data)}
        if isinstance(out, dict) and out.get("rqid") not in (None, msg["rqid"]):
            out["_rqid_echo"] = out.get("rqid")      # cached-response detector
        return out


def describe(o: dict) -> str:
    """Diagnostics without leaking identity values."""
    if o.get("result") == "NOERR" and not any(
            k.startswith("_") for k in o):
        return "NOERR"
    keep = {k: o[k] for k in ("result", "msgid", "msg", "error_code",
                              "error", "errcode", "show_info",
                              "maintenance_end_time",
                              "_status", "_err", "_len",
                              "_rqid_echo") if k in o}
    return json.dumps(keep, ensure_ascii=False, default=str)


def login(g: Gate, reqs) -> tuple[bool, dict]:
    m = dict(gc.decode(reqs["CMD_LOGIN"]))           # byte-for-byte game body
    m["rqid"] = next_rq()                            # fresh: bypass rqid cache
    m["client_version"] = CV                         # 6.1.0 executes (STACK 3)
    m["s_keyword"] = gc.s_keyword(CV, BUILD)         # CONST ^ client_version
    r = g.send(m)
    if r.get("result") != "NOERR" or not r.get("session_id"):
        return False, r
    g.sid = r["session_id"]
    pui = r.get("pes_user_info") or {}
    g.uid = pui.get("user_id") or m.get("user_id") or 0
    g.base = {k: m[k] for k in ("my_platform", "lang", "region", "platform")
              if k in m}
    return True, r


def relay_quality(g: Gate, reqs) -> dict:
    cap = gc.decode(reqs["CMD_SET_GAMERELAY_QUALITY"])
    now = int(time.time())
    ql = [dict(e, last_update=now) for e in cap["quality_list"]]
    m = g.envelope("CMD_SET_GAMERELAY_QUALITY")
    m["quality_list"] = ql
    return g.send(m)


def create_room(g: Gate) -> dict:
    m = g.envelope("CMD_CREATEJOIN_ROOM")
    m["core_settings"] = {k: CFG[k] for k in CS_KEYS}
    m["match_settings"] = {"match_env": {k: CFG[k] for k in ME_KEYS}}
    m["event_account_type"] = CFG["event_account_type"]
    m["address_ipv4"] = {k: CFG["a4." + k] for k in NET_KEYS}
    m["address_ipv6"] = {k: CFG["a6." + k] for k in NET_KEYS}
    m["platform_session_id_info"] = {"ps_session_id": CFG["psid"],
                                     "xb_session_id": CFG["xbsid"]}
    m["strike_arena_selected_info"] = [{"player_id": 1, "costume_id": 0}]
    return g.send(m)


def main() -> int:
    live = "--live" in sys.argv
    for arg in sys.argv[1:]:
        if arg.startswith("--mode="):
            CFG["mode"] = arg.split("=", 1)[1]
        if arg.startswith("--kind="):
            CFG["kind"] = arg.split("=", 1)[1]

    reqs, resps = load_capture()
    print("capture: %d requests / %d responses decoded"
          % (len(reqs), len(resps)))

    lm = gc.decode(reqs["CMD_LOGIN"])
    env_keys = ("msgid", "rqid", "user_id", "session_id", "my_platform",
                "s_keyword", "lang", "region", "platform", "client_version")
    print("offline: CMD_LOGIN %d fields, envelope complete=%s, auth_code=%s"
          % (len(lm),
             all(k in lm for k in env_keys),
             "present" if lm.get("auth_code") else "MISSING"))
    qlm = gc.decode(reqs["CMD_SET_GAMERELAY_QUALITY"])
    print("offline: SET_GAMERELAY_QUALITY quality_list=%d entries"
          % len(qlm.get("quality_list", [])))
    if not live:
        return 0

    g = Gate()
    t0 = time.time()
    ok, r = login(g, reqs)
    if not ok:
        print("login        -> %s" % describe(r))
        return 1
    print("login        -> NOERR  session acquired (%d chars)"
          % len(g.sid))
    time.sleep(PACE)

    q = relay_quality(g, reqs)
    print("relay quality-> %s" % describe(q))
    if q.get("result") != "NOERR":
        return 1
    time.sleep(PACE)

    o = create_room(g)
    print("create room  -> %s" % describe(o))
    if o.get("result") == "NOERR":
        print("room_id      -> %s" % json.dumps(o.get("room_id")))
        print("elapsed      -> %.1fs" % (time.time() - t0))
        return 0
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
