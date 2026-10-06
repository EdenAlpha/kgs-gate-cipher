#!/usr/bin/env python3
"""Call a KGS command once its route is known.

The last link. `analyse_capture.py` recovers the `path` values the game actually
sends, together with the `packMode` and the `req` payload beside each one. This
takes such a route and replays it, so a recovered route can be confirmed
against the live endpoint rather than merely read.

It also carries the identity the game sends at login, recovered in plaintext
from the NTL gate call in the capture:

    titleCode PES2022, locale US, version 6.0.1, apiLevel 4
    uid     3c5aad3c6b8425c611ebe2f5da6c25af
    opt     22011111
    libVer  1.17.1-Android-15

Usage:
    python kgs_call.py --path /session/get --req '{"token":"..."}'
    python kgs_call.py --path / --req '{}' --samples 5
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

IDENTITY = {
    "titleCode": "PES2022",
    "locale": "US",
    "version": "6.0.1",
    "apiLevel": "4",
    "uid": "3c5aad3c6b8425c611ebe2f5da6c25af",
    "opt": 22011111,
    "libVer": "1.17.1-Android-15",
}


def one(path, payload, pack):
    try:
        r = call(path, payload, pack, str(uuid.uuid4()), settle=4.0)
    except Exception as e:
        return {"err": "%s: %s" % (type(e).__name__, e)}
    st, gm = None, ""
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = unquote_plus(h.get("grpc-message", ""))
    out = {"http": None, "grpc": st, "message": gm, "cmd": None, "res": None}
    for _f, h in r["headers"]:
        if ":status" in h:
            out["http"] = h[":status"]
    d = r["data"]
    if len(d) >= 5:
        mlen = int.from_bytes(d[1:5], "big")
        dec = command_response(d[5:5 + mlen])
        out["cmd"] = dec.get("id")
        out["res"] = dec.get("res")
        out["packMode"] = dec.get("packMode")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True)
    ap.add_argument("--req", default="{}")
    ap.add_argument("--pack", type=int, default=0, choices=(0, 1))
    ap.add_argument("--samples", type=int, default=1)
    ap.add_argument("--with-identity", action="store_true",
                    help="merge the recovered app identity into the payload")
    a = ap.parse_args()

    payload = a.req
    if a.with_identity:
        try:
            obj = json.loads(a.req)
            if not isinstance(obj, dict):
                obj = {}
        except Exception:
            obj = {}
        for k, v in IDENTITY.items():
            obj.setdefault(k, v)
        payload = json.dumps(obj)

    print("path    %s" % a.path)
    print("pack    %d (%s)" % (a.pack, "JSON" if a.pack == 0 else "MSGPACK"))
    print("req     %s" % (payload[:300] + ("..." if len(payload) > 300 else "")))
    print()

    results = []
    for i in range(max(1, a.samples)):
        r = one(a.path, payload, a.pack)
        results.append(r)
        if "err" in r:
            print("  sample %d: ERROR %s" % (i + 1, r["err"]))
        else:
            print("  sample %d: http=%s grpc=%s cmd=%s"
                  % (i + 1, r["http"], r["grpc"], r["cmd"]))
            if r["message"]:
                print("           message: %s" % r["message"][:200])
            if r["res"]:
                print("           res: %s" % r["res"][:400])
        if i + 1 < a.samples:
            import time
            time.sleep(0.7)

    if len(results) > 1:
        tally = collections.Counter(
            (r.get("grpc"), r.get("cmd")) for r in results if "err" not in r)
        print("\nmodal outcome over %d samples: %s"
              % (len(results), tally.most_common(1)[0] if tally else "n/a"))
        if len(tally) > 1:
            print("  (varies -- the endpoint has a ~0.7%% transient, so a single")
            print("   sample is not conclusive; see repeat_test.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
