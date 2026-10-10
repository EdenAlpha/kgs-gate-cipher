#!/usr/bin/env python3
"""chain3.py -- both seated -> squads -> sides -> ready -> session check
(GET/SET_GAME_SESSION_CHECK_RES echo) -> game_id -> START_GAME ->
heartbeat -> phase walk (halftime -> fulltime) -> goals -> SET_GAME_RESULT
-> read the score back.

The session-check echo (finish.py, pre-wipe proven) is what flips
is_check_finished to YES and unblocks START_GAME from ERR_DATABASE.
CMD_HEARTBEAT_GRPC after kickoff is the never-run experiment against the
DISCONN_HB birth-stamp.

  python chain3.py            offline check
  python chain3.py --live     full run
"""
import json
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import gate_client as gc  # noqa: E402
from room1 import (BUILD, CFG, PACE, Gate, create_room, describe,  # noqa: E402
                   login, load_capture, next_rq, relay_quality)
from room2 import BOT_FILE, join_body, login_bot, NET  # noqa: E402
from room_info_shape import SENSITIVE, shape  # noqa: E402
from sendreq_probe import getrequested, num_users, sendreq  # noqa: E402

SENSITIVE.update({"id", "serial"})

CFG["mode"] = "CUSTOM"
CFG["kind"] = "SINGLE"
DIAG_CV = "6.1.1"


def show(o) -> str:
    return json.dumps(shape(o), ensure_ascii=False, default=str)


def at_cv(m: dict, cv: str) -> dict:
    m = dict(m)
    m["client_version"] = cv
    m["s_keyword"] = gc.s_keyword(cv, BUILD)
    return m


def args_ok(r: dict) -> bool:
    return r.get("result") != "ERR_INVALIDARG"


def diag(g: Gate, build) -> tuple[dict, bool]:
    """build() -> fresh body (fresh rqid); send at 6.1.1, never executes."""
    r = g.send(at_cv(build(), DIAG_CV))
    msg = r.get("msg") or ""
    ok = args_ok(r)
    print("  diag -> %s%s" % (r.get("result"),
                              (" | " + msg[:200]) if msg else ""))
    return r, ok


def find_key(o, key):
    if isinstance(o, dict):
        if key in o:
            return o[key]
        for v in o.values():
            f = find_key(v, key)
            if f is not None:
                return f
    elif isinstance(o, list):
        for v in o:
            f = find_key(v, key)
            if f is not None:
                return f
    return None


# ---------------------------------------------------------------- bodies ---

def entry_side(g: Gate, rid: int, side: str, leader: bool) -> dict:
    m = g.envelope("CMD_SET_ROOM_USER_ENTRY_SIDE")
    m["room_id"] = {"id": rid}
    m["entry_side"] = side
    m["is_entry_side_leader"] = "YES" if leader else "NO"
    return m


def match_ready(g: Gate, rid: int) -> dict:
    m = g.envelope("CMD_SET_ROOM_MATCH_READY")
    m["room_id"] = {"id": rid}
    m["is_single_matching"] = "YES"
    m["gamerelay_measure_result"] = "MEASUREING"
    m["address_ipv4"] = dict(NET)
    m["address_ipv6"] = dict(NET)
    return m


def game_session(g: Gate, rid: int) -> dict:
    m = g.envelope("CMD_GET_GAME_SESSION")
    m["room_id"] = [str(rid)]
    return m


def as_map(v):
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return dict(v[0])
    return {}


def as_int(v, default=0):
    return v if isinstance(v, int) and not isinstance(v, bool) else default


def heartbeat(g: Gate, msec: int = 5000) -> dict:
    m = g.envelope("CMD_HEARTBEAT_GRPC")
    m["heartbeat_interval_msec"] = msec
    return g.send(m)


def stadium() -> dict:
    return {"stadium_id": 0, "custom_stadium_name": "",
            "stadium_color1": 0, "stadium_color2": 0, "stadium_color3": 0,
            "stadium_color4": 0, "goalnet_pattern": 0, "goalnet_color1": 0,
            "goalnet_color2": 0, "pitch_pattern": 0, "entrance_set": 0,
            "bill_set": 0, "pitchside_objects": [], "goal_effect1": 0,
            "goal_effect2": 0, "kickoff_effect": 0,
            "has_invalid_assets": "NO"}


def gcd() -> dict:
    """CMD_CHANGE_GAMEPHASE nested game_check_data (phase_chain.py proven)."""
    return {"match_time_frame": 0, "match_time_tick": 0, "com_stop_info": 0,
            "entry_check_data": 0, "ball_move_max_speed": 0,
            "gameplayer_parameter_check_data_list": [],
            "opponent_gameplayer_parameter_check_data_list": [],
            "custom_stadium": stadium(),
            "golazo_info": {"golazo_count_list": []}}


def change_phase(g: Gate, game_id, phase: str, gtimer: int) -> dict:
    m = g.envelope("CMD_CHANGE_GAMEPHASE")
    m["game_id"] = game_id
    m["phase"] = phase
    m["gtimer"] = gtimer
    m["game_check_data"] = gcd()
    return g.send(m)


def add_score(g: Gate, game_id, goal_user, side, scorer,
              minute: int) -> dict:
    m = g.envelope("CMD_ADD_SCORE")
    m.update(game_id=game_id, goal_user_id=goal_user, goal_side=side,
             goal_gameplayer_id=scorer, goal_player_side=side,
             assist_user_id=goal_user, assist_side=side,
             assist_gameplayer_id=scorer, assist_player_side=side,
             gtimer=minute * 60, phase="END", match_minute=minute)
    return g.send(m)


def sgr_entry(p: dict, starting: str) -> dict:
    gidobj = p.get("gameplayer_id") or {}
    return {"gameplayer_id": {"id": gidobj.get("id"),
                              "serial": gidobj.get("serial")},
            "rating": 0, "play_time": 90, "position": "GK",
            "is_starting_member": starting, "is_join_game": "YES",
            "oap": 0, "base_value": 0, "is_man_of_the_match": "NO"}


def sgr_stats(score: int, poss: int, shots: int, on: int) -> dict:
    return {"score": score, "ball_possession": poss, "shots": shots,
            "shots_on_goal": on, "faul": 0, "faul_offside": 0,
            "corner_kick": 0, "free_kick": 0, "pass_success_rate": 0,
            "cross": 0, "pass_cut": 0, "tackle": 0, "save": 0}


def sgr_request(game_id, mine, theirs, home_score, away_score,
                abnormal: str) -> dict:
    """CMD_SET_GAME_RESULT -- root is exactly three keys (finish.py)."""
    players = [sgr_entry(p, "YES" if i < 11 else "NO")
               for i, p in enumerate(mine)]
    match_result = {
        "game_id": game_id, "abnormalend_reason": abnormal,
        "is_problem": "NO",
        "user_network_status": {"is_stun_keep_alive_failed": "NO",
                                "is_network_blocked_disconn": "NO",
                                "is_background_timeout": "NO",
                                "is_background_at_match": "NO"},
        "ex_flag": "NO", "pk_flag": "NO", "error_code": "0",
        "myteam_player_list": players,
        "match_stat_side_info_list": [sgr_stats(home_score, 55, 7, 4),
                                      sgr_stats(away_score, 45, 3, 1)],
        "use_team_style": "NONE", "event_record": 0, "restart_num": 0,
        "control_style": 0,
        "coop_score": {"total": 0, "shoot": 0, "pass": 0, "dribble": 0,
                       "offense_positioning": 0, "duel": 0,
                       "defense_positioning": 0},
        "ml_event_match_bonus": {"count": 0, "golazo_info": {}},
        "use_setting_multi_formation": "NO",
    }
    game_check = {
        "match_time_frame": 0, "match_time_tick": 0, "com_stop_info": 0,
        "entry_check_data": 0, "ball_move_max_speed": 0,
        "custom_stadium": stadium(), "golazo_info": {},
    }
    analyst = {"match_json": "", "advice_json": "",
               "advice_info_match": {"game_id": game_id},
               "is_invalid_advice": ""}
    return {"match_result": match_result, "game_check_data": game_check,
            "analyst_set_game_result_info": analyst}


def user_squad(g: Gate, target: int) -> dict:
    m = g.envelope("CMD_GET_USER_SQUAD")
    m["target_user_id"] = target
    return m


def start_game(g: Gate, game_id, team_id, home, away) -> dict:
    m = g.envelope("CMD_START_GAME")
    m["match_category"] = "LOBBY_ROOM_MATCH_1VS1"
    m["game_id"] = game_id
    m["side"] = "HOME"
    m["player_list_home"] = home
    m["player_list_away"] = away
    m["team_id"] = team_id
    m["is_vs_aimatch"] = "NO"
    return m


def game_id_of(g: Gate, rid: int) -> dict:
    m = g.envelope("CMD_GET_GAME_ID")
    m["room_id"] = {"id": rid}
    return g.send(m)


def check_match_enable(g: Gate) -> dict:
    m = g.envelope("CMD_CHECK_MATCH_ENABLE")
    m["event_id"] = 0
    return g.send(m)


def game_team_list(g: Gate) -> dict:
    return g.send(g.envelope("CMD_GET_GAME_TEAM_LIST"))


def get_game_id(g: Gate, rid: int):
    """Try the builder form first, then server-side fallbacks (one per rqid)."""
    forms = [
        ("map-int",  {"room_id": {"id": rid}}),
        ("flat-int", {"room_id": rid}),
        ("str",      {"room_id": str(rid)}),
        ("arr-str",  {"room_id": [str(rid)]}),
        ("map-str",  {"room_id": {"id": str(rid)}}),
        ("roominfo", {"mode": "CUSTOM", "id": 0, "room_id": {"id": rid},
                      "event_id": 0, "user_compe_id": 0,
                      "is_room_search": "NO"}),
    ]
    for label, extra in forms:
        m = g.envelope("CMD_GET_GAME_ID")
        m.update(extra)
        r = g.send(m)
        gid = find_key(r, "game_id")
        print("  form %-9s -> %-16s game_id=%s"
              % (label, r.get("result"), "yes" if gid is not None else "no"))
        if r.get("result") == "NOERR" and gid is not None:
            return gid
        time.sleep(PACE)
    return None


def squad_list(sq: dict) -> list:
    """[{gameplayer_id:{id,serial}}, ...] for CMD_START_GAME (pre-wipe proven)."""
    out = []
    for p in ((sq.get("squad_data") or {}).get("player_list") or []):
        gid = p.get("gameplayer_id") or {}
        if gid.get("id"):
            out.append({"gameplayer_id": {"id": gid["id"],
                                          "serial": gid["serial"]}})
    return out


def room_state(g: Gate, rid: int) -> dict:
    m = g.envelope("CMD_GET_ROOM_INFO")
    m.update({"mode": "CUSTOM", "id": 0, "room_id": {"id": rid},
              "event_id": 0, "user_compe_id": 0, "is_room_search": "NO"})
    r = g.send(m)
    return (r.get("room_info") or {}) if r.get("result") == "NOERR" else {}


# ------------------------------------------------------------------- run ---

def main() -> int:
    if "--live" not in sys.argv:
        print("offline check: imports ok, use --live")
        return 0
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

    def pace():
        time.sleep(PACE)

    owner = Gate()
    ok, r = login(owner, reqs)
    print("owner login  -> %s" % (r.get("result") if not ok else "NOERR"))
    if not ok:
        print("  %s" % describe(r))
        return 1
    pace()
    q = relay_quality(owner, reqs)
    print("owner quality-> %s" % q.get("result"))
    if q.get("result") != "NOERR":
        return 1
    pace()
    o = create_room(owner)
    rid = ((o.get("room_id") or {}).get("id")) if o.get("result") == "NOERR" else None
    print("create room  -> %s  room_id=%s" % (o.get("result"), rid))
    if not rid:
        print("  %s" % describe(o))
        return 1
    pace()

    botg = Gate()
    okb, rb = login_bot(botg, reqs, bot)
    print("bot login    -> %s" % (rb.get("result") if not okb else "NOERR"))
    if not okb:
        print("  %s" % describe(rb))
        return 1
    pace()
    qb = relay_quality(botg, reqs)
    print("bot quality  -> %s" % qb.get("result"))
    if qb.get("result") != "NOERR":
        return 1
    pace()

    # -- the proven join ladder ----------------------------------------
    a = sendreq(botg, 0, rid)
    print("bot sendreq  -> %s" % a.get("result"))
    pace()
    b = sendreq(owner, botg.uid, rid)
    print("owner invite -> %s" % b.get("result"))
    pace()
    c = getrequested(botg, owner.uid)
    print("bot getreq   -> %s" % c.get("result"))
    if c.get("result") != "NOERR":
        print("  %s" % describe(c))
        return 1
    pace()
    jb = join_body(botg, rid)
    jb["mode"] = "CUSTOM"
    e = botg.send(jb)
    print("bot join     -> %s" % e.get("result"))
    if e.get("result") != "NOERR":
        print("  %s" % describe(e))
        return 1
    pace()
    n = num_users(owner, rid)
    print("seated       -> %s" % n)
    if n != 2:
        return 1
    pace()

    # -- squad reads ----------------------------------------------------
    sq_o = owner.send(user_squad(owner, owner.uid))
    print("owner squad  -> %s" % sq_o.get("result"))
    if sq_o.get("result") != "NOERR":
        print("  %s" % describe(sq_o))
        return 1
    pace()
    sq_b = botg.send(user_squad(botg, botg.uid))
    print("bot squad    -> %s" % sq_b.get("result"))
    if sq_b.get("result") != "NOERR":
        print("  %s" % describe(sq_b))
        return 1
    pace()

    team_data = sq_o.get("team_data") or {}
    team_id = team_data.get("base_team_id") if isinstance(team_data, dict) else None
    if team_id is None:
        team_id = find_key(sq_o, "base_team_id")
    print("team_id      -> %s" % (type(team_id).__name__ if team_id is not None else "MISSING"))
    if team_id is None:
        return 1

    # -- entry sides ----------------------------------------------------
    for side, leader, g in (("HOME", True, owner), ("AWAY", False, botg)):
        who = "owner" if g is owner else "bot  "
        _, okd = diag(g, lambda: entry_side(g, rid, side, leader))
        if not okd:
            print("entry_side [%s] input rejected -- stopping" % who)
            return 1
        pace()
        es = g.send(entry_side(g, rid, side, leader))
        print("entry_side [%s] -> %s" % (who, es.get("result")))
        if es.get("result") != "NOERR":
            print("  %s" % describe(es))
            return 1
        pace()

    # -- ready ----------------------------------------------------------
    for g in (owner, botg):
        who = "owner" if g is owner else "bot  "
        _, okd = diag(g, lambda: match_ready(g, rid))
        if not okd:
            print("match_ready [%s] input rejected -- stopping" % who)
            return 1
        pace()
        mr = g.send(match_ready(g, rid))
        print("match_ready [%s] -> %s" % (who, mr.get("result")))
        if mr.get("result") != "NOERR":
            print("  %s" % describe(mr))
            return 1
        pace()

    # -- go_match flips server-side once both are ready ------------------
    go = "NO"
    for _ in range(6):
        ri = room_state(owner, rid)
        go = ri.get("is_go_match")
        if go == "YES":
            break
        time.sleep(1.0)
    print("go_match     -> %s" % go)
    pace()

    # -- game session ----------------------------------------------------
    gs = owner.send(game_session(owner, rid))
    print("game_session -> %s keys=%s" % (gs.get("result"), ",".join(sorted(gs))))
    print("  %s" % show({k: v for k, v in gs.items()
                         if k not in ("result", "msgid", "rqid")}))
    pace()

    # -- report the session check, echoing the server's own values -------
    # (finish.py proven: this is what flips is_check_finished to YES and
    #  unblocks CMD_START_GAME from ERR_DATABASE)
    gr = as_map(gs.get("gamerelay"))
    sycom = gs.get("game_sycom")
    for tag, g, self_u, opp_u in (("owner", owner, owner.uid, botg.uid),
                                  ("bot  ", botg, botg.uid, owner.uid)):
        b = {
            "game_sycom": sycom if isinstance(sycom, str) else "",
            "error_code": "NOERR",
            "gamerelay": {"name": gr.get("name", ""),
                          "region": gr.get("region", ""),
                          "ip_addr": gr.get("ip_addr", ""),
                          "port": as_int(gr.get("port"))},
            "failed_reason": 0,
            "is_lobby": "YES",
            "room_id": {"id": rid},
            "statistical_data": {
                "user_id_list": [self_u, opp_u], "matching_num": 2,
                "answer": "", "antenna_min": as_int(gs.get("ping")),
                "error_code": "NOERR", "link_type": "",
                "create_session_time": as_int(gs.get("connecting_start_time")),
                "background_times": "",
            },
        }
        m = g.envelope("CMD_SET_GAME_SESSION_CHECK_RES")
        m.update(b)
        r = g.send(m)
        print("check_res [%s] -> %s" % (tag, r.get("result")))
        if r.get("result") != "NOERR":
            print("  %s" % describe(r))
        pace()

    m = owner.envelope("CMD_GET_GAME_SESSION_CHECK_RES")
    m["room_id"] = {"id": rid}
    m["is_lobby"] = "YES"
    m["game_entry_user_list"] = [owner.uid, botg.uid]
    gcr = owner.send(m)
    print("check_state  -> %s (%s)"
          % (gcr.get("is_check_finished"), gcr.get("result")))
    pace()

    # -- game_id (its own command) ---------------------------------------
    game_id = get_game_id(owner, rid)
    if game_id is None:
        print("game_id MISSING in every form -- stopping")
        return 1
    print("game_id      -> found (%s)" % type(game_id).__name__)
    pace()

    # -- START_GAME (finish.py proven order: owner XI first) -------------
    home = squad_list(sq_o)
    away = squad_list(sq_b)
    print("lineups      -> home=%d away=%d team_id=%s"
          % (len(home), len(away), team_id))
    if len(home) < 11 or len(away) < 11:
        print("a side has fewer than 11 players -- stopping")
        return 1

    sg = None
    for label, g, hl, al in (("owner XI", owner, home[:11], away[:11]),
                             ("owner 23", owner, home, away)):
        sg = g.send(start_game(g, game_id, team_id, hl, al))
        print("start_game [%s] -> %s" % (label, sg.get("result")))
        pace()
        if sg.get("result") == "NOERR":
            break
    if not sg or sg.get("result") != "NOERR":
        print("  %s" % describe(sg or {}))
        return 1
    print("  %s" % show({k: v for k, v in sg.items()
                         if k not in ("result", "msgid", "rqid")}))

    # -- heartbeat experiment (never run pre-wipe) ------------------------
    for tag, g in (("owner", owner), ("bot  ", botg)):
        hb = heartbeat(g)
        print("heartbeat [%s] -> %s (%s)"
              % (tag, hb.get("result"), hb.get("errcode")))
        pace()

    # -- phases: halftime converts to fulltime ---------------------------
    for p in ("1ST_15MIN", "1ST_30MIN", "BREAK1", "2ND", "2ND_30MIN", "END"):
        r = change_phase(owner, game_id, p, 900)
        ri = room_state(owner, rid)
        print("phase %-10s -> %-14s room gamephase=%s"
              % (p, r.get("result"), ri.get("gamephase")))
        if r.get("result") != "NOERR":
            print("  %s" % describe(r))
        pace()
        if p == "BREAK1":
            for tag, g in (("owner", owner), ("bot  ", botg)):
                hb = heartbeat(g)
                print("heartbeat [%s] -> %s" % (tag, hb.get("result")))
                pace()

    # -- goals (finish.py proven: owner channel, phase=END) --------------
    scorer_h = home[0]["gameplayer_id"] if home else None
    scorer_a = away[0]["gameplayer_id"] if away else None
    for who, side, minute, scorer in ((owner.uid, "HOME", 12, scorer_h),
                                      (owner.uid, "HOME", 34, scorer_h),
                                      (botg.uid, "AWAY", 61, scorer_a)):
        r = add_score(owner, game_id, who, side, scorer, minute)
        print("goal %2d' %-4s -> %s (%s)"
              % (minute, side, r.get("result"), r.get("errcode")))
        pace()

    # -- publish the result (root = 3 keys) ------------------------------
    for abnormal in ("NONE", "DISCONN_HB"):
        req = sgr_request(game_id, home, away, 2, 1, abnormal)
        m = owner.envelope("CMD_SET_GAME_RESULT")
        m.update(req)
        r = owner.send(m)
        print("set_result [%-10s] -> %-14s (%s)"
              % (abnormal, r.get("result"), r.get("errcode")))
        time.sleep(1.2)
        if r.get("result") == "NOERR":
            break

    # -- read the score back ---------------------------------------------
    m = owner.envelope("CMD_CHECK_GAME_RESULT")
    m["game_id"] = game_id
    c = owner.send(m)
    print("check_result -> %s (%s)" % (c.get("result"), c.get("errcode")))
    print("  %s" % json.dumps(shape(c.get("game_end_result")),
                              ensure_ascii=False, default=str)[:2500])
    pace()
    for tag, g in (("owner", owner), ("bot  ", botg)):
        m = g.envelope("CMD_GET_GAME_RESULT")
        m["game_id"] = game_id
        r = g.send(m)
        mr = r.get("match_result")
        slim = {k: v for k, v in (mr or {}).items()
                if k in ("score", "home", "away", "gameend_reason",
                         "abnormalend_reason", "match_stat_side_info_list")}
        print("get_result [%s] -> %s get_match_result=%s"
              % (tag, r.get("result"), r.get("get_match_result")))
        if mr:
            print("  score-ish=%s" % json.dumps(shape(slim), default=str,
                                                ensure_ascii=False)[:900])
        pace()

    ri = room_state(owner, rid)
    print("final        -> gamephase=%s go_match=%s"
          % (ri.get("gamephase"), ri.get("is_go_match")))
    print("elapsed      -> %.1fs" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
