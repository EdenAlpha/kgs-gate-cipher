"""Probe the relay for an exec/shell endpoint.

The relay is reachable in ~1s while the git round trip is 60-120s, so if it
can run a shell command on the device that is a far better control path.
Prints what each candidate endpoint returned instead of guessing.
"""
import json
import os
import urllib.error
import urllib.request

cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "relay.json")))
URL, TOK = cfg["url"], cfg["token"]

probes = [
    ("GET /exec", "/exec?token=%s&cmd=id" % TOK, None),
    ("GET /sh", "/sh?token=%s&cmd=id" % TOK, None),
    ("GET /shell", "/shell?token=%s&cmd=id" % TOK, None),
    ("POST /exec", "/exec", {"token": TOK, "cmd": "id"}),
    ("POST /sh", "/sh", {"token": TOK, "cmd": "id"}),
    ("POST /shell", "/shell", {"token": TOK, "cmd": "id"}),
    ("GET /", "/?token=%s" % TOK, None),
]

for name, path, body in probes:
    url = URL + path
    try:
        if body is None:
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=25) as r:
            print("%-12s rc=%s %s" % (name, r.status, r.read()[:300]))
    except urllib.error.HTTPError as e:
        print("%-12s rc=%s %s" % (name, e.code, e.read()[:200]))
    except Exception as e:
        print("%-12s ERR %s" % (name, e))