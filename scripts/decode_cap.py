#!/usr/bin/env python3
"""decode_cap.py -- print the STRUCTURE (keys/types/lengths) of one captured
command's request and response, masking credential values.

  python decode_cap.py CMD_CREATE_USER
"""
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\kgs-gate-cipher")

import gate_client as gc  # noqa: E402
from room1 import load_capture  # noqa: E402

SENSITIVE = {"auth_code", "hash", "session_id", "user_id", "s_keyword",
             "device_identifier", "auth_key", "auth_token", "sign",
             "password", "user_name", "guest_token", "ticket", "key"}


def is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return len(s) % 2 == 0 and len(s) > 8
    except ValueError:
        return False


def shape(v, key=None, depth=0):
    if isinstance(v, dict):
        return {k: shape(x, k, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        out = [shape(x, key, depth + 1) for x in v[:2]]
        if len(v) > 2:
            out.append("...(%d total)" % len(v))
        return out
    if key in SENSITIVE:
        if isinstance(v, str):
            tag = ":hex" if is_hex(v) else ""
            return "<%s:%d%s>" % ("str", len(v), tag)
        return "<%s>" % type(v).__name__
    return v


def main():
    if len(sys.argv) < 2:
        print("usage: decode_cap.py CMD_NAME")
        return 1
    cmd = sys.argv[1]
    reqs, resps = load_capture()
    print("captured: " + ", ".join(sorted(reqs)))
    if cmd in reqs:
        print("--- REQ %s ---" % cmd)
        import json
        print(json.dumps(shape(gc.decode(reqs[cmd])), indent=1,
                         ensure_ascii=False, default=str))
    else:
        print("no REQ for %s" % cmd)
    if cmd in resps:
        print("--- RESP %s ---" % cmd)
        import json
        print(json.dumps(shape(gc.decode(resps[cmd])), indent=1,
                         ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
