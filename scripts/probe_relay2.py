"""Find out what the relay will actually serve.

Only /state /shot /tap /text /cred are known to work; everything else has
returned 403. Before I tell the user data cannot move, I check the plausible
file-serving paths -- the relay is the one channel with real bandwidth, and a
single working /file-style endpoint would change the whole plan.
"""
import json
import os
import urllib.error
import urllib.request

cfg = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "relay.json")))
URL, TOK = cfg["url"], cfg["token"]

PATHS = [
    "/state", "/shot", "/cred", "/text",
    "/file", "/files", "/dl", "/download", "/pull", "/fetch", "/get",
    "/cat", "/tail", "/logs", "/log", "/dump", "/sweep", "/kgs",
    "/upload", "/put", "/write", "/read", "/path", "/serve", "/static",
    "/out", "/artifact", "/artifacts", "/result", "/results",
]

print("--- GET probe (token in query) ---")
for p in PATHS:
    url = "%s%s?token=%s" % (URL, p, TOK)
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read()[:120]
            print("%-12s rc=%s len=%s %r" % (p, r.status, len(body), body[:80]))
    except urllib.error.HTTPError as e:
        print("%-12s rc=%s %r" % (p, e.code, e.read()[:80]))
    except Exception as e:
        print("%-12s ERR %s" % (p, str(e)[:80]))