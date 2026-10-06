"""Does the server actually validate the 40-byte `sign` cookie?

Reversal says `sign` is a per-request nonce: the HMAC key is
    <seed "Xrq-RtAF_91MAE82"> + "|" + to_string(mt_random ^ nanotime)
so it cannot be recomputed offline.  If the server checked it we could never
forge gate traffic, so it is worth knowing whether it is checked at all.

Four read-only probes, in this order, because each one only means something if
the one before it passes:

  1. control-ip   GET a deliberately fake gate script name
                  -> 404 proves this IP is accepted; 403 proves it is not
                     (and per AGENTS.md that is where the work stops)
  2. control-good POST the recorded CMD_GET_SERVER_ENV byte-for-byte
                  -> 200 proves the session is still alive, which is the
                     baseline every other result is compared against
  3. bad-sign     same request, Cookie sign replaced by same-length garbage
  4. no-sign      same request, no Cookie header at all

Only CMD_GET_SERVER_ENV is used: it is a read, so replaying it has no side
effect.  Nothing is spoofed to get past an access control; if probe 1 returns
403 we report and stop.

The sign value itself is never printed -- only its length and first 8 chars.
"""
import base64
import re
import ssl
import sys
import time
import http.client

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\sign_probe.txt"

HOST = "pes22-game.cs.konami.net"
PATH = "/pes22/gate/gate_CMD_GET_SERVER_ENV.php"

UA = "PES/1.0 (ANDROID 14; 0; redroid14_arm64_only; 0; 6.0.1; ; 11.0.1; )"

lines = []


def say(s=""):
    lines.append(s)


# ------------------------------------------------- recorded request --------
def load_request():
    """Body from flows.log, sign from the first gate Cookie in flows.mitm."""
    raw = open(LOG, "rb").read().split(b"\n")
    body = None
    want = PATH.rsplit("/", 1)[1].encode()
    i = 0
    while i < len(raw):
        if raw[i].startswith(b"### REQ POST ") and want in raw[i]:
            j = i + 1
            while j < len(raw) and not raw[j].startswith(b"### "):
                if raw[j].startswith(b"REQHEX: "):
                    body = bytes.fromhex(raw[j][8:].strip().decode())
                j += 1
            break
        i += 1
    m = re.search(rb"sign=([A-Za-z0-9+/=]+)", open(MITM, "rb").read())
    sign = m.group(1) if m else None
    return body, sign


BODY, SIGN = load_request()
if not BODY or not SIGN:
    say("FATAL: could not extract body=%s sign=%s" % (bool(BODY), bool(SIGN)))
    open(OUT, "w", encoding="utf-8").write("\n".join(lines))
    sys.exit(1)

say("recorded request")
say("  path        %s" % PATH)
say("  body        %d bytes  head=%s" % (len(BODY), BODY[:8].hex()))
say("  sign        %d chars  head=%r" % (len(SIGN), SIGN[:8]))
say("")

# --------------------------------------------------------- probes ----------
BASE = [
    ("Accept-Language", "jp"),
    ("User-Agent", UA),
    ("pes-custom-encrypt", "AES256"),
    ("Accept-Encoding", "gzip"),
    ("Content-Encoding", "gzip"),
    ("Content-Type", "application/x-www-form-urlencoded"),
    ("Connection", "Keep-Alive"),
]


def send(label, method, path, body, extra=None, drop=()):
    hs = [(k, v) for k, v in BASE if k not in drop]
    if extra:
        hs.extend(extra)
    ctx = ssl.create_default_context()
    t0 = time.time()
    try:
        c = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=25)
        c.request(method, path, body=body, headers=dict(hs))
        r = c.getresponse()
        data = r.read()
        code, reason = r.status, r.reason
        ctype = r.getheader("Content-Type", "-")
        clen = r.getheader("Content-Length", "-")
        c.close()
        ok = True
    except Exception as e:                                     # noqa: BLE001
        code, reason, data, ctype, clen, ok = "-", repr(e), b"", "-", "-", False
    dt = time.time() - t0
    preview = "".join(chr(x) if 32 <= x < 127 else "." for x in data[:160])
    say("--- %s ---" % label)
    say("    %s %s" % (method, path))
    say("    -> %s %s   %d bytes   %.2fs   ct=%s cl=%s"
        % (code, reason, len(data), dt, ctype, clen))
    say("    body: %s" % preview)
    if data[:2] == b"\x1f\x8b":
        try:
            import gzip
            d2 = gzip.decompress(data)
            say("    gunzip -> %d bytes: %s" % (len(d2), d2[:160]))
        except Exception as e:                                 # noqa: BLE001
            say("    gunzip failed: %r" % e)
    say("")
    return code, data


say("=" * 70)
say("PROBES")
say("=" * 70)

c1, d1 = send("1 control-ip   (fake script name, expect 404)",
              "GET", "/pes22/gate/gate_CMD_ZZZ_PROBE_NOT_A_SCRIPT.php", None,
              drop=("Content-Type", "Content-Encoding"))

if str(c1) == "403":
    say("STOP: 403 from this address. AGENTS.md: Konami's 403 stops the work.")
else:
    time.sleep(2)
    c2, d2 = send("2 control-good (byte-exact replay, expect 200)",
                  "POST", PATH, BODY,
                  extra=[("Cookie", "sign=%s;" % SIGN.decode())])
    time.sleep(2)
    bad = base64.b64encode(bytes(40)).decode()                # 56 chars, valid b64
    assert len(bad) == len(SIGN), (len(bad), len(SIGN))
    c3, d3 = send("3 bad-sign     (same length, all-zero)",
                  "POST", PATH, BODY,
                  extra=[("Cookie", "sign=%s;" % bad)])
    time.sleep(2)
    c4, d4 = send("4 no-sign      (no Cookie header)",
                  "POST", PATH, BODY,
                  drop=("Content-Type",))

    say("=" * 70)
    say("VERDICT")
    say("=" * 70)
    say("  control-ip  = %s" % c1)
    say("  control-good= %s (%d bytes)" % (c2, len(d2)))
    say("  bad-sign    = %s (%d bytes)" % (c3, len(d3)))
    say("  no-sign     = %s (%d bytes)" % (c4, len(d4)))
    say("")
    if str(c2) != "200":
        say("  INCONCLUSIVE: the good-sign replay did not return 200, so")
        say("  the session is dead and no comparison can be made.")
    elif d3 == d2 and str(c3) == str(c2):
        say("  VERDICT: sign is NOT checked. bad-sign is byte-identical to")
        say("           the good replay -> sign is a nonce, not an auth.")
    elif d4 == d2 and str(c4) == str(c2):
        say("  VERDICT: sign is NOT checked (absent == present).")
    else:
        say("  VERDICT: sign IS checked. responses differ, so the cookie is")
        say("           validated and must be forged correctly.")

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("wrote %s (%d lines)" % (OUT, len(lines)))
