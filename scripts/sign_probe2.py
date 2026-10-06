"""Is `sign` cryptographically bound to the body, or only structurally sane?

Probe run 1 established: correct sign -> 200, all-zero sign -> 500, no sign -> 500,
and a fake script name -> 404 (our IP is accepted, session is alive).

The all-zero sign could have been rejected by a shape test (40 non-zero bytes,
plausible IV, whatever) rather than by verifying a MAC.  So swap in signs that
are structurally perfect but from the wrong source:

  control   body1 + sign1   -> must be 200 again (session still alive)
  wrong-body body1 + sign2  -> sign2 is a real recorded sign for a DIFFERENT
                               body; 40 real bytes, right shape
  random    body1 + random  -> 40 fresh non-zero bytes, right shape

Only the Cookie changes in each.  200 on either of the last two means the
server checks shape only; 500 on both means the value is bound to the body.

No credential is printed -- only lengths and first 8 chars.
"""
import base64
import os
import re
import ssl
import time
import http.client

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\sign_probe2.txt"

HOST = "pes22-game.cs.konami.net"
UA = "PES/1.0 (ANDROID 14; 0; redroid14_arm64_only; 0; 6.0.1; ; 11.0.1; )"
BASE = [
    ("Accept-Language", "jp"),
    ("User-Agent", UA),
    ("pes-custom-encrypt", "AES256"),
    ("Accept-Encoding", "gzip"),
    ("Content-Encoding", "gzip"),
    ("Content-Type", "application/x-www-form-urlencoded"),
    ("Connection", "Keep-Alive"),
]

lines = []


def say(s=""):
    lines.append(s)


# ------------------------------------------------- recorded material -------
raw = open(LOG, "rb").read().split(b"\n")
reqs, name = [], None
for line in raw:
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else "?"
    elif line.startswith(b"REQHEX: ") and name:
        reqs.append((name, line[8:].strip()))
        name = None

signs = [m.group(1) for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)",
                                          open(MITM, "rb").read())]
b1, h1 = reqs[0]
b2, h2 = reqs[1]
B1 = bytes.fromhex(h1.decode())
B2 = bytes.fromhex(h2.decode())
S1, S2 = signs[0].decode(), signs[1].decode()
RND = base64.b64encode(os.urandom(40)).decode()

say("body1 = %s (%d bytes)   body2 = %s (%d bytes)" % (b1, len(B1), b2, len(B2)))
say("sign1 len=%d head=%r   sign2 len=%d head=%r   random len=%d"
    % (len(S1), S1[:8], len(S2), S2[:8], len(RND)))
say("")

PATH1 = "/pes22/gate/gate_%s.php" % b1
PATH2 = "/pes22/gate/gate_%s.php" % b2
assert b1.startswith("CMD_") and b2.startswith("CMD_"), (b1, b2)


def send(label, path, body, sign):
    hs = dict(BASE)
    if sign is not None:
        hs["Cookie"] = "sign=%s;" % sign
    ctx = ssl.create_default_context()
    t0 = time.time()
    try:
        c = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=25)
        c.request("POST", path, body=body, headers=hs)
        r = c.getresponse()
        data = r.read()
        code, reason = r.status, r.reason
        c.close()
    except Exception as e:                                     # noqa: BLE001
        code, reason, data = "-", repr(e), b""
    say("  %-16s -> %s %-22s %5d bytes  %.2fs"
        % (label, code, reason, len(data), time.time() - t0))
    return str(code), data


say("=" * 66)
say("PROBES")
say("=" * 66)
c_ctl, d_ctl = send("control(sign1)", PATH1, B1, S1)
time.sleep(2)
c_wb, d_wb = send("wrong-body", PATH1, B1, S2)
time.sleep(2)
c_rnd, d_rnd = send("random", PATH1, B1, RND)
time.sleep(2)
c_own, d_own = send("pair2-correct", PATH2, B2, S2)

say("")
say("=" * 66)
say("VERDICT")
say("=" * 66)
say("  control  = %s (%d)" % (c_ctl, len(d_ctl)))
say("  wrong-body = %s (%d)" % (c_wb, len(d_wb)))
say("  random     = %s (%d)" % (c_rnd, len(d_rnd)))
say("  pair2      = %s (%d)" % (c_own, len(d_own)))
say("")
if c_ctl != "200":
    say("  INCONCLUSIVE: control no longer 200, session/endpoint changed.")
elif c_wb == "200" and c_rnd == "200":
    say("  VERDICT: sign is NOT bound to the body -- shape only.")
    say("           A valid sign from any request would be accepted.")
elif c_wb == "200":
    say("  VERDICT: wrong-body accepted -> sign is not bound to body;")
    say("           the all-zero sign failed a structural check.")
elif c_rnd == "200":
    say("  VERDICT: random accepted -> zero specifically rejected.")
else:
    say("  VERDICT: sign IS verified against the body. Wrong sign (real or")
    say("           random, both 40 valid bytes) -> 500, correct -> 200.")

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("wrote %s (%d lines)" % (OUT, len(lines)))
