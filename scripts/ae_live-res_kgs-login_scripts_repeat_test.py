#!/usr/bin/env python3
"""Re-test the `method` hypothesis with repetition instead of single samples.

What happened: one sample of `{"method": "CMD_GET_SESSION_ID"}` came back
`grpc-status: 14 UNAVAILABLE` while every other payload shape returned the
default route, and that was read as "the payload selects the command". A sweep
of all 384 `CMD_*` names then found only 2 rejections, and this name among the
non-rejections -- so the original observation did not reproduce.

The reason is known by now: the endpoint returns `502 / UNAVAILABLE`
intermittently, so a single sample cannot distinguish "this input is rejected"
from "this request happened to hit a bad moment". That has already produced one
false conclusion (the `content-type` theory) and nearly a second.

So every candidate is sent N times and classified by its **modal** outcome, with
the spread reported. An input is only interesting if it reliably produces
something other than the default route.
"""
from __future__ import annotations

import collections
import json
import os
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

N = 5
CASES = [
    ("path=/  req={}",            "/", {}),
    ("path=/  req={method:X}",    "/", {"method": "CMD_GET_SESSION_ID"}),
    ("path=/  req={cmd:X}",       "/", {"cmd": "CMD_GET_SESSION_ID"}),
    ("path=/  req={command:X}",    "/", {"command": "CMD_GET_SESSION_ID"}),
    ("path=/  req={name:X}",      "/", {"name": "CMD_GET_SESSION_ID"}),
    ("path=/  req={type:X}",      "/", {"type": "CMD_GET_SESSION_ID"}),
    ("path=/  req={id:X}",        "/", {"id": "CMD_GET_SESSION_ID"}),
    ("path=/  req={path:X}",      "/", {"path": "CMD_GET_SESSION_ID"}),
    ("path=/  req={action:X}",    "/", {"action": "CMD_GET_SESSION_ID"}),
    ("path=/  req={op:X}",        "/", {"op": "CMD_GET_SESSION_ID"}),
    ("path=/  req={function:X}",  "/", {"function": "CMD_GET_SESSION_ID"}),
    ("path=/  req={service:X}",   "/", {"service": "CMD_GET_SESSION_ID"}),
    ("path=/  req={command:X,id:1}", "/", {"command": "CMD_GET_SESSION_ID",
                                           "id": "1"}),
    ("path=/  req=not json",      "/", "@@notjson@@"),
]


def one(path, payload):
    try:
        r = call(path, payload, 0, str(uuid.uuid4()), settle=2.5)
    except Exception as e:
        return "ERR:%s" % type(e).__name__
    st = None
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
    d = r["data"]
    if len(d) >= 5:
        mlen = int.from_bytes(d[1:5], "big")
        dec = command_response(d[5:5 + mlen])
        return "%s/%s" % (st, dec.get("id"))
    return "%s/none" % st


def main() -> int:
    print("%d samples per case, path kept at \"/\"\n" % N)
    print("%-34s %-34s %s" % ("case", "outcomes", "verdict"))
    for label, path, obj in CASES:
        payload = obj if isinstance(obj, str) else json.dumps(obj)
        seen = collections.Counter()
        for _ in range(N):
            seen[one(path, payload)] += 1
        top, cnt = seen.most_common(1)[0]
        spread = ", ".join("%s x%d" % (k, v) for k, v in seen.most_common())
        if top.endswith("CMD_END_CONNECTION"):
            verdict = "default route"
        elif top.startswith("14"):
            verdict = "rejected"
        else:
            verdict = "*** INTERESTING ***"
        print("%-34s %-34s %s" % (label, spread, verdict), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
