#!/usr/bin/env python3
"""mint.py -- create the bot's second account via the captured CMD_CREATE_USER flow.

The capture proves the flow: CREATE_USER (no auth_code in request) returns a
server-generated auth_code + session_id + user_code for a brand-new account
(the owner account was born this way on 2026-10-01).

Ordered attempts, stopping at the first NEW identity:
  1. replay byte-for-byte (patch rqid / client_version / s_keyword)
  2. + fresh user_name        (if the replay dedupes to the owner)
  3. + fresh device_identifier (if still deduped)

Then verifies the identity with a CMD_LOGIN using the bot's auth_code.

Credentials are written ONLY to work\\bot_identity.json (local; work\\ is not
inside any git repo) -- never printed, never committed.
"""
import json
import random
import sys
import time

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import gate_client as gc  # noqa: E402
from room1 import Gate, CV, BUILD, PACE, describe, load_capture  # noqa: E402

OUT = r"C:\Users\Administrator\Documents\Default Project\work\bot_identity.json"


def uid_of(o):
    return ((o.get("pes_user_info") or {}).get("user_id")
            if isinstance(o, dict) else None)


def main():
    reqs, resps = load_capture()
    owner_uid = gc.decode(reqs["CMD_LOGIN"]).get("user_id")
    print("owner uid loaded: %s" % ("yes" if owner_uid else "no"))

    g = Gate()                       # shared rqid counter across attempts
    base = gc.decode(reqs["CMD_CREATE_USER"])

    def attempt(tag, mutate=None):
        m = dict(base)
        if mutate:
            mutate(m)
        g.rqid += 1
        m["rqid"] = g.rqid
        m["client_version"] = CV
        m["s_keyword"] = gc.s_keyword(CV, BUILD)
        r = g.send(m)
        res = r.get("result")
        uid = uid_of(r)
        new = uid is not None and uid != owner_uid
        print("  create[%s] -> %s  uid_new=%s" % (tag, res, new))
        if res != "NOERR":
            print("    %s" % describe(r))
        return r, new

    DEDUPE = ("ERR_USERNAME_ALREADY_EXISTS",)

    def can_retry(res):
        # NOERR with the owner uid = silent dedupe; the named error = loud one
        return res in DEDUPE or res == "NOERR"

    r1, new = attempt("as-is")
    if not new and can_retry(r1.get("result")):
        name = "PLinkBot%04d" % random.randint(0, 9999)
        print("  retry with user_name=%r" % name)
        r2, new = attempt("rename", lambda m: m["pes_user_info"].update(
            user_name=name))
        if r2.get("result") == "NOERR":
            r1 = r2
    if not new and can_retry(r1.get("result")):
        dev = "%064x" % random.getrandbits(256)
        print("  retry with fresh device_identifier")
        r3, new = attempt("device", lambda m: m["device"].update(
            device_identifier=dev))
        r1 = r3 if r3.get("result") == "NOERR" else r1

    if not new or r1.get("result") != "NOERR":
        print("no new identity (result=%s) -- stopping" % r1.get("result"))
        return 1

    bot = {
        "user_id": uid_of(r1),
        "auth_code": r1.get("auth_code"),
        "user_code": r1.get("user_code"),
        "session_id": r1.get("session_id"),
        "created": int(time.time()),
        "note": "bot identity minted via captured CMD_CREATE_USER; local only",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(bot, fh, indent=1)
    print("  bot identity saved -> bot_identity.json")

    # The full CREATE response carries entry_info (23 players + coach) --
    # the only place a new account's roster is ever visible.  SET_MYCLUB_
    # ENTRY_INFO needs it; keep it locally (credentials, never commit).
    with open(r"C:\Users\Administrator\Documents\Default Project\work\bot_create.json",
              "w", encoding="utf-8") as fh:
        json.dump(r1, fh, indent=1)
    print("  full CREATE response saved -> bot_create.json")

    # verify: CMD_LOGIN with the bot's auth_code
    lm = dict(gc.decode(reqs["CMD_LOGIN"]))
    g.rqid += 1
    lm["rqid"] = g.rqid
    lm["user_id"] = bot["user_id"]
    lm["auth_code"] = bot["auth_code"]
    lm["session_id"] = ""
    lm["hash"] = gc.decode(reqs["CMD_CREATE_USER"]).get("hash", lm.get("hash"))
    lm["client_version"] = CV
    lm["s_keyword"] = gc.s_keyword(CV, BUILD)
    lr = g.send(lm)
    ok = lr.get("result") == "NOERR" and bool(lr.get("session_id"))
    match = ok and uid_of(lr) == bot["user_id"]
    print("  bot login   -> %s  uid_match=%s" % (lr.get("result"), match))
    if not ok:
        print("    %s" % describe(lr))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
