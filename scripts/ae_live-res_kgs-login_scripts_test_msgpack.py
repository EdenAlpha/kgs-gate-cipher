#!/usr/bin/env python3
"""Does the server accept a MessagePack `req` under PACK_MODE_MSGPACK?

`CommandRequest.req` is a `string`, and `packMode` picks the encoding:
`PACK_MODE_JSON = 0`, `PACK_MODE_MSGPACK = 1`. Everything sent so far has been
JSON. The game almost certainly uses msgpack, and it is worth knowing whether the
server accepts it *before* a route is found -- if msgpack were rejected the same
way malformed JSON is, then a found route would still fail.

Tested with 5 samples each, because the endpoint has a ~0.7% transient and a
single sample has already produced two false conclusions here.
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
from msgpack import enc  # noqa: E402

N = 5


def one(payload, pack):
    try:
        r = call("/", payload, pack, str(uuid.uuid4()), settle=2.5)
    except Exception as e:
        return ("ERR", type(e).__name__)
    st = None
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
    d = r["data"]
    if len(d) >= 5:
        mlen = int.from_bytes(d[1:5], "big")
        dec = command_response(d[5:5 + mlen])
        return (st, dec.get("id") or "", (dec.get("res") or "")[:50])
    return (st, "", "")


def trial(label, payload, pack):
    seen = collections.Counter()
    for _ in range(N):
        seen[one(payload, pack)] += 1
    (st, cmd, res), n = seen.most_common(1)[0]
    verdict = ("default route" if cmd == "CMD_END_CONNECTION"
               else "REAL" if cmd else "rejected (14)" if st == "14"
               else "other")
    print("  %-44s %-34s %s"
          % (label, ", ".join("%s/%s x%d" % (k[0], k[1] or "-", c)
                              for k, c in seen.most_common()), verdict))
    return verdict


def main() -> int:
    print("path=/ , %d samples each\n" % N)

    print("A. packMode = 0 (JSON)")
    trial("req={} (empty json map)", json.dumps({}), 0)
    trial("req=[] (empty json array)", json.dumps([]), 0)

    print("\nB. packMode = 1 (MSGPACK)")
    trial("req=0x80 (empty map)", enc({}).decode("latin1"), 1)
    trial("req=0x90 (empty array)", enc([]).decode("latin1"), 1)
    trial("req=0xc0 (nil)", enc(None).decode("latin1"), 1)
    trial("req=0xa0 (empty str)", enc("").decode("latin1"), 1)
    trial("msgpack {'a':1}", enc({"a": 1}).decode("latin1"), 1)

    print("\nC. mismatches, to see which side is validated")
    trial("packMode=1 but req is JSON text", json.dumps({}), 1)
    trial("packMode=0 but req is msgpack bytes", enc({}).decode("latin1"), 0)
    trial("packMode=1, req is not msgpack at all", "not-msgpack", 1)

    print("\nD. is the msgpack payload hex-escaped in transit?")
    raw = enc({"a": 1}).decode("latin1")
    print("  raw msgpack for {'a':1} = %s" % raw.encode("latin1").hex())
    trial("hex string of the msgpack", raw.encode("latin1").hex(), 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
