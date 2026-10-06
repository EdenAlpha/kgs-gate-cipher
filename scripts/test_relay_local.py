"""Local self-test for kgs-login/live/relay.py - no device, no CI run."""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import urllib.request
import urllib.error

HERE = tempfile.mkdtemp(prefix="relaytest-")
TAPS = os.path.join(HERE, "taps.log")

os.environ["RELAY_TOKEN"] = "a" * 36
spec = importlib.util.spec_from_file_location(
    "relay", r"C:\Users\Administrator\Documents\Default Project"
    r"\peerlink-efootball-disconnects\kgs-login\live\relay.py")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
relay.TAPS = TAPS

CALLS = []


def fake_run(*args, timeout=30):
    CALLS.append(list(args))
    if "screencap" in args:
        return 0, b"\x89PNG\r\n\x1a\n fake"
    return 0, b""


relay.run = fake_run

srv = relay.HTTPServer(("127.0.0.1", 8010), relay.H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = "http://127.0.0.1:8010"
TOK = os.environ["RELAY_TOKEN"]
fails = []


def get(path, token=TOK):
    try:
        with urllib.request.urlopen("%s%s?token=%s" % (BASE, path, token)) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def post(path, body):
    req = urllib.request.Request("%s%s" % (BASE, path),
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + ("  " + extra if extra else ""))
    if not cond:
        fails.append(name)


# --- state ---
rc, body = get("/state")
check("state ok with good token", rc == 200 and json.loads(body)["ok"] is True)

# --- tap ---
rc, body = post("/tap", {"token": TOK, "x": 500, "y": 700})
d = json.loads(body) if rc == 200 else {}
check("tap ok, returns dt_ms", rc == 200 and "dt_ms" in d)
check("tap issued as input swipe hold", any(
    "swipe" in c for c in CALLS))

# --- tap: bad token / out of range ---
rc, _ = post("/tap", {"token": "wrong", "x": 500, "y": 700})
check("tap bad token -> 403", rc == 403)
rc, _ = post("/tap", {"token": TOK, "x": 99999, "y": 700})
check("tap out of range -> 403", rc == 403)

# --- text ---
CALLS.clear()
rc, body = post("/text", {"token": TOK, "s": "player.one+tag@example.com"})
d = json.loads(body) if rc == 200 else {}
check("text ok, returns dt_ms", rc == 200 and "dt_ms" in d)
check("text sent via input text",
      any("text" in c and "player.one+tag@example.com" in " ".join(c) for c in CALLS))

# --- text: shell metacharacters must be refused ---
for bad in ["a; rm -rf /", "a$(id)", "a`id`", "a && b", "x" * 121, "",
            "#comment", "-abc", "a\nb", "a'b", 'a"b', "a<b>c", "a|b",
            "a(b)", "a*b", "a[1]", "a\\b", "a{1}", " a"]:
    rc, _ = post("/text", {"token": TOK, "s": bad})
    check("text %r refused" % bad, rc == 403)

# --- text: a realistic password with dashes/bang still types ---
CALLS.clear()
rc, _ = post("/text", {"token": TOK, "s": "Pass-w0rd!2026"})
check("dash/bang password accepted", rc == 200 and any(
    "Pass-w0rd!2026" in " ".join(c) for c in CALLS))

# --- text: spaces become %s ---
CALLS.clear()
rc, _ = post("/text", {"token": TOK, "s": "hi there"})
check("space typed as %%s", rc == 200 and any(
    "hi%sthere" in " ".join(c) for c in CALLS))

# --- shot ---
rc, body = get("/shot")
check("shot returns png", rc == 200 and body[:4] == b"\x89PNG")
rc, _ = get("/shot", token="nope")
check("shot bad token -> 403", rc == 403)

# --- unknown path ---
rc, _ = get("/exec")
check("unknown path -> 403", rc == 403)

# --- log written, and NO text content in it ---
with open(TAPS) as fh:
    log = fh.read()
check("taps.log written", "tap\t" in log and "shot\t" in log and "text\t" in log)
check("text logged by length only",
      "len=" in log and "player.one" not in log and "hi there" not in log)

srv.shutdown()
print("\n%d passed, %d failed" % (0 if fails else 0, len(fails)))
sys.exit(1 if fails else 0)
