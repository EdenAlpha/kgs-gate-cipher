"""Is the AES-256 body key sitting in libUE4.so as raw bytes?

Every key search so far only tested READABLE TEXT keys -- 1,383,714 of them.
A real 32-byte AES key is arbitrary bytes, never words, so that whole family
of searches could not have found it.  This closes that gap.

Photocopier, not guessing: no key is invented.  Every 32-byte window of the
game's own binary is tried in turn against a response Konami's server actually
sent us, and only the server's own ciphertext is used as the test.

Test
----
Recorded gate responses are 2400 / 2352 bytes and are not printable, so the
working shape is   response = IV[16] || AES-256-CBC(key, ct).
Two layouts are tried per offset because the IV arrangement was never proven:

    A   pt = AES_dec(ct0) XOR response[0:16]     (explicit IV prefix)
    B   pt = AES_dec(ct0)                        (IV = 16 zero bytes)

A candidate survives only if the first block comes out as printable ASCII
(JSON) or begins with the gzip magic -- and then it must ALSO unlock every
other recorded response.  A wrong key satisfies a 16-byte printable test by
chance about 1 time in 160 million, so a confirmed hit is trustworthy.

Ends with a printed YES or NO.
"""
import re
import sys
import time
from Crypto.Cipher import AES

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
PROG = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_scan_progress.txt"

GZIP = b"\x1f\x8b\x08"


def is_pt(b):
    """All-printable ASCII, or a gzip stream start.

    bytes has no isprintable(); min/max over 16 bytes is a C-level test and
    needs no per-byte loop.  Full range 0x20..0x7e, deliberately strict.
    """
    return b[:3] == GZIP or (min(b) >= 0x20 and max(b) <= 0x7E)


def xor16(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")


# ------------------------------------------------------- recorded replies ---
# Pair each request with the response that follows it, and keep ONLY gate
# replies.  This matters: many non-gate bodies are plain gzip (never
# encrypted), and confirming a genuine key against one of those would reject
# it -- a false NO.  The gate replies are the encrypted JSON ones.
raw = open(LOG, "rb").read().split(b"\n")
gate, other = [], []
path = None
for line in raw:
    if line.startswith(b"### REQ POST ") or line.startswith(b"### REQ GET "):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
    elif line.startswith(b"RESPHEX: "):
        try:
            body = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            path = None
            continue
        (gate if (path and "/gate/" in path) else other).append((path, body))
        path = None

# richest first: the big encrypted gate replies are the useful ones
gate.sort(key=lambda t: len(t[1]), reverse=True)
targets = [b for _, b in gate if len(b) >= 64][:6]
if not targets:
    print("NO -- no gate response bodies found in flows.log "
          "(parsed %d other replies)" % len(other))
    raise SystemExit(1)

# widest gate response drives the scan; the rest only confirm
main = targets[0]
IV = main[0:16]
CT0 = main[16:32]

print("gate responses   : %d   (other replies: %d)" % (len(gate), len(other)))
print("scan target      : %d bytes from %s" % (len(main), gate[0][0]))
print("                 : IV=%s" % IV.hex())
print("                 : ct0=%s" % CT0.hex())
print("confirm against  : %d gate replies (lengths %s)"
      % (len(targets), [len(t) for t in targets]))
print("")

# ------------------------------------------------------------- candidates --
LIMIT = 0
if len(sys.argv) > 1:
    LIMIT = int(sys.argv[1])
    print("*** BENCH MODE: first %d offsets only ***" % LIMIT)

data = open(SO, "rb").read()
n = len(data)
stop = n - 31 if LIMIT == 0 else min(n - 31, LIMIT)
print("file             : %d bytes, testing offsets 0 .. %d" % (n, stop - 1))
print("")


def unlocks_all(key):
    c = AES.new(key, AES.MODE_ECB)
    for r in targets:
        iv, ct0 = r[0:16], r[16:32]
        d = c.decrypt(ct0)
        if not (is_pt(d) or is_pt(xor16(d, iv))):
            return False
    return True


t0 = time.time()
hits = []
checked = 0
step = 5_000_000
next_report = step
last = t0

for off in range(0, stop):
    key = data[off:off + 32]
    d = AES.new(key, AES.MODE_ECB).decrypt(CT0)
    if is_pt(d) or is_pt(xor16(d, IV)):
        print("  candidate at offset %d (0x%x) -- verifying against all %d"
              % (off, off, len(targets)))
        if unlocks_all(key):
            hits.append((off, key))
            print("  CONFIRMED on every recorded response")
    checked += 1
    if checked >= next_report:
        now = time.time()
        rate = step / max(now - last, 1e-6)
        eta = (stop - checked) / max(rate, 1e-6)
        line = ("progress %9d / %d  (%.1f%%)  %.0f offsets/s  ETA %.0fs"
                % (checked, stop, 100.0 * checked / stop, rate, eta))
        print(line, flush=True)
        open(PROG, "w", encoding="utf-8").write(line + "\n")
        next_report += step
        last = now

dt = time.time() - t0
print("")
print("tested %d offsets in %.1f s (%.0f offsets/s)"
      % (checked, dt, checked / max(dt, 1e-6)))
print("raw candidates that looked printable on the scan target: see above")
print("confirmed on ALL responses: %d" % len(hits))
print("")
if hits:
    print("YES -- key found in libUE4.so")
    for off, key in hits:
        print("     offset 0x%x  key %s" % (off, key.hex()))
else:
    print("NO -- no 32-byte window of libUE4.so decrypts the recorded "
          "responses")
