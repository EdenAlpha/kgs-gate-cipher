"""Re-test every 32-byte window of libUE4.so with a PKCS#7 padding oracle.

Why this exists
---------------
aes_scan.py returned NO, but its acceptance rule was only

    gzip magic  OR  16 bytes all inside 0x20..0x7e

That means it could only ever confirm a key whose FIRST decrypted block is
printable text.  If the gate replies decrypt to msgpack -- which is what the
*requests* are known to be -- the correct key decrypts to binary and the scan
would have thrown it away.  So that NO does not actually close the question.

The padding rule does close it.  CBC+PKCS7 always ends with a block whose last
byte is the pad length 1..16, and every byte of the pad equals it, whatever the
payload type underneath.  A wrong key satisfies that by chance ~0.4% of the
time, so requiring it on all N replies makes a false positive ~0.4^(N-1):

    6 replies  ->  ~1e-13   over 1.6e8 offsets: zero expected

Only the LAST block is needed to test the pad, so the fast-reject pass is one
16-byte ECB decrypt per offset, then the full set only for the ~6e5 survivors.

Three layouts are tried because the IV arrangement was never proven:

    1  IV prefix, or none   pt = D(ct[-1]) XOR ct[-2]     body = IV || ct
    2  IV suffix            pt = D(ct[-1]) XOR ct[-2]     body = ct || IV
                           (layout 2's last ct block sits 16 bytes earlier,
                            so it is a genuinely different computation)

Prints a final YES or NO.
"""
import re
import sys
import time
from Crypto.Cipher import AES

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
PROG = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_pad_progress.txt"

GZIP = b"\x1f\x8b\x08"

try:
    import msgpack as _mp
except ImportError:
    _mp = None


def pad_ok(block):
    """True if this 16 bytes is a legal PKCS#7 final block."""
    n = block[15]
    if n < 1 or n > 16:
        return False
    return block[16 - n:] == bytes([n]) * n


def xor16(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")


def describe(b):
    """What kind of payload is this?  Used only to label a hit."""
    if b[:3] == GZIP:
        return "gzip"
    if _mp is not None:
        try:
            _mp.unpackb(b, strict_map_key=False)
            return "msgpack"
        except Exception:
            pass
    if b and min(b) >= 0x20 and max(b) <= 0x7E:
        return "printable"
    return "binary"


# ------------------------------------------------------- recorded exchanges --
raw = open(LOG, "rb").read().split(b"\n")
exch, path, pend_req = [], None, None
for line in raw:
    if line.startswith(b"### REQ "):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
        pend_req = None
    elif line.startswith(b"REQHEX: "):
        try:
            pend_req = bytes.fromhex(line[8:].strip().decode())
        except ValueError:
            pend_req = None
    elif line.startswith(b"RESPHEX: "):
        try:
            rb = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            rb = None
        if rb is not None and path:
            exch.append((path, pend_req, rb))
        path, pend_req = None, None

gate = [e for e in exch if "/gate/" in e[0] and len(e[2]) >= 64]
gate.sort(key=lambda t: len(t[2]), reverse=True)
targets = [e[2] for e in gate[:6]]
reqs = [e[1] for e in gate[:6] if e[1] and len(e[1]) >= 64]

if not targets:
    print("NO -- no gate responses found in flows.log (%d exchanges parsed)"
          % len(exch))
    raise SystemExit(1)

print("gate exchanges    : %d" % len(gate))
print("confirm on        : %d replies, lengths %s"
      % (len(targets), [len(t) for t in targets]))
print("also tested       : %d gate requests, lengths %s"
      % (len(reqs), [len(r) for r in reqs]))
print("oracle            : PKCS#7 pad valid on EVERY reply (content-agnostic)")
print("layouts           : 1 = IV||ct or bare ct,  2 = ct||IV")
print("")

LIMIT = 0
if len(sys.argv) > 1:
    LIMIT = int(sys.argv[1])
    print("*** BENCH MODE: first %d offsets only ***" % LIMIT)
    print("")

data = open(SO, "rb").read()
n = len(data)
stop = n - 31 if LIMIT == 0 else min(n - 31, LIMIT)
print("file              : %d bytes, offsets 0 .. %d" % (n, stop - 1))
print("")


def pad_block(ec, body, layout):
    """Decrypt the final CBC block under the chosen IV layout; None if bad pad.

    layout 1: body = [IV] || ct, so the last two ct blocks are body[-32:-16],
              body[-16:].
    layout 2: body = ct || IV,   so the last two ct blocks are body[-48:-32],
              body[-32:-16].
    """
    if layout == 1:
        if len(body) < 48:
            return None
        prev, last = body[-32:-16], body[-16:]
    else:
        if len(body) < 64:
            return None
        prev, last = body[-48:-32], body[-32:-16]
    pt = xor16(ec.decrypt(last), prev)
    return pt if pad_ok(pt) else None


def opens_every(key):
    """Full set of replies must all show a legal final pad."""
    ec = AES.new(key, AES.MODE_ECB)
    for lay in (1, 2):
        if all(pad_block(ec, r, lay) is not None for r in targets):
            return lay
    return None


def decrypt_all(key, body, lay):
    """Full CBC decrypt so we can describe the payload."""
    if lay == 1:
        iv, ct = body[:16], body[16:]
    else:
        iv, ct = body[-16:], body[:-16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(ct)


t0 = time.time()
hits = []
checked = 0
probe = targets[0]
step = 5_000_000
next_report = step
last = t0

for off in range(0, stop):
    key = data[off:off + 32]
    ec = AES.new(key, AES.MODE_ECB)

    # fast reject: one reply, one block
    fast = None
    for lay in (1, 2):
        if pad_block(ec, probe, lay) is not None:
            fast = lay
            break

    if fast is not None:
        # ~0.4% of random keys pass on one reply, so do not log them -- only
        # the ones that survive all six matter.  (~640k false alarms otherwise.)
        lay = opens_every(key)
        if lay:
            hits.append((off, key, lay))
            print("  CONFIRMED on every recorded reply (layout %d)" % lay,
                  flush=True)

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
print("pad-valid on all replies: %d" % len(hits))
print("")

if not hits:
    print("NO -- no 32-byte window of libUE4.so satisfies PKCS#7 padding on "
          "every recorded gate reply")
else:
    print("YES -- key found in libUE4.so")
    for off, key, lay in hits:
        print("     offset 0x%x   layout %d   key %s" % (off, lay, key.hex()))
        pt = decrypt_all(key, targets[0], lay)
        print("       payload: %s   first 96 bytes:" % describe(pt))
        print("         %s" % pt[:96].hex())
        if reqs:
            ec = AES.new(key, AES.MODE_ECB)
            rl = None
            for l in (1, 2):
                if all(pad_block(ec, r, l) is not None for r in reqs):
                    rl = l
            print("       gate requests open with this key: %s%s"
                  % ("yes" if rl else "no",
                     " (layout %d)" % rl if rl else ""))
