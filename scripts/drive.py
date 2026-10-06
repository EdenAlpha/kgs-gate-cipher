"""Drive the phone through the relay:  drive.py state|shot|tap|text|..."""
import json
import os
import sys
import time
import urllib.error
import urllib.request

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay.json")
SHOTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")
cfg = json.load(open(CFG))
URL, TOK = cfg["url"], cfg["token"]
os.makedirs(SHOTS, exist_ok=True)


def get(path, raw=False):
    try:
        with urllib.request.urlopen("%s%s?token=%s" % (URL, path, TOK), timeout=60) as r:
            b = r.read()
            return r.status, (b if raw else b.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)


def post(path, body):
    req = urllib.request.Request("%s%s" % (URL, path),
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 2
    cmd = a[0]
    t0 = time.time()
    if cmd == "state":
        print(get("/state")[1])
    elif cmd == "shot":
        name = a[1] if len(a) > 1 else str(int(time.time()))
        rc, png = get("/shot", raw=True)
        if rc == 200 and png[:4] == b"\x89PNG":
            p = os.path.join(SHOTS, name + ".png")
            open(p, "wb").write(png)
            print("%s  %d bytes  roundtrip=%.2fs" % (p, len(png), time.time() - t0))
        else:
            print("SHOT FAILED rc=%s len=%s" % (rc, len(png) if isinstance(png, bytes) else png))
            return 1
    elif cmd == "tap":
        x, y = int(a[1]), int(a[2])
        ms = int(a[3]) if len(a) > 3 else 250
        print(post("/tap", {"token": TOK, "x": x, "y": y, "ms": ms}))
    elif cmd == "text":
        print(post("/text", {"token": TOK, "s": a[1]}))
    elif cmd == "cred":
        print(post("/cred", {"token": TOK, "which": a[1]}))
    else:
        print("unknown:", cmd)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
