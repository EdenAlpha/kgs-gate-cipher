"""Look at the raw 40 bytes of the 13 recorded `sign` values.

The key derivation is now name-verified from .rela.plt:

    key = "Xrq-RtAF_91MAE82" + "|" + decimal(mt_random ^ clock_gettime_ns)

That is time+random, so the server could not recompute it -- yet the live probe
showed it accepts a recorded sign hours later and rejects a random one.  The
only way both hold is if part of the key material is carried in the sign
itself (or the prefix is a constant the server already knows).

So: decode all 13, show the raw bytes as hex AND as text, and compare the
first half against the second half across requests.  Facts only, no inference.
"""
import base64
import re
import os

BASE = r"C:\Users\Administrator\AppData\Local\Temp\2"
LOG = os.path.join(BASE, "rec2", "flows.mitm")
LOG2 = os.path.join(BASE, "rec2", "flows.log")
OUT = os.path.join(BASE, "sign_bytes.txt")

out = []


def say(s=""):
    out.append(str(s))


# ---------------------------------------------------------------- harvest ---
# `sign=<b64>` appears in the Cookie header of every gate request.
signs = []
for path in (LOG, LOG2):
    if not os.path.exists(path):
        continue
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            for m in re.finditer(r"sign=([A-Za-z0-9+/]{40,80}=*)", line):
                signs.append((os.path.basename(path), lineno, m.group(1)))

# de-duplicate on the encoded value, keep first sighting
seen = {}
for src, lineno, enc in signs:
    seen.setdefault(enc, (src, lineno))

encoded = list(seen.keys())
say("distinct sign values: %d  (raw matches incl. repeats: %d)"
    % (len(encoded), len(signs)))
say("")

if not encoded:
    say("NO sign= values found -- check the capture paths")
    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    raise SystemExit(1)

decoded = []
for enc in encoded:
    try:
        raw = base64.b64decode(enc)
    except Exception as e:                                    # noqa: BLE001
        say("  decode FAILED (%s): %s..." % (e, enc[:24]))
        continue
    decoded.append((enc, raw))

say("decoded lengths: %s" % sorted({len(r) for _, r in decoded}))
say("")

printable = lambda b: "".join(chr(c) if 32 <= c < 127 else "." for c in b)

say("=" * 78)
say("RAW BYTES  (hex | text)")
say("=" * 78)
for i, (enc, raw) in enumerate(decoded):
    say("%2d  %s" % (i, raw.hex()))
    say("    |%s|" % printable(raw))
say("")

# ------------------------------------------------- does anything repeat? ----
say("=" * 78)
say("DO ANY BYTES STAY THE SAME ACROSS ALL REQUESTS?")
say("=" * 78)
if len({len(r) for _, r in decoded}) == 1:
    n = len(decoded[0][1])
    stable = [i for i in range(n)
              if len({r[i] for _, r in decoded}) == 1]
    say("positions identical in every sign (%d bytes): %s"
        % (len(stable), stable if stable else "NONE"))
    if stable:
        b0 = decoded[0][1]
        say("  constant bytes      = %s" % b0[stable].hex())
        say("  as text             = |%s|" % printable(b0[stable]))
    say("")
    say("first half identical in every sign : %s"
        % (len({r[: n // 2] for _, r in decoded}) == 1))
    say("last  half identical in every sign : %s"
        % (len({r[n // 2:] for _, r in decoded}) == 1))
    say("distinct values overall            : %d of %d"
        % (len({r for _, r in decoded}), len(decoded)))
say("")

# ---------------------------------------- is the seed carried in the sign? --
SEED = b"Xrq-RtAF_91MAE82"
say("=" * 78)
say("IS THE KEY SEED PRESENT IN THE RAW SIGN BYTES?")
say("=" * 78)
hit = [i for i, (_, r) in enumerate(decoded) if SEED in r]
say("  seed found verbatim in       : %s" % (hit if hit else "NONE"))
say("  any sign contains '|' (0x7c) : %s"
    % ([i for i, (_, r) in enumerate(decoded) if 0x7C in r] or "NONE"))
say("  fully printable ASCII        : %s"
    % ([i for i, (_, r) in enumerate(decoded)
        if all(32 <= c < 127 for c in r)] or "NONE"))
say("")
say("Note: a 17-char ASCII seed + '|' + digits would only fit in 40 bytes")
say("      together with a 20-byte MAC if the number were <= 3 digits.")
say("      Nothing above supports that -- recorded for the record either way.")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
