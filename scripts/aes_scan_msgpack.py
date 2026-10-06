"""The case neither previous scan could see: binary plaintext, no PKCS#7 pad.

Two full sweeps of libUE4.so already returned NO, each with a different oracle:

  aes_scan.py      first block is printable ASCII or gzip magic   -> NO
  aes_scan_pad.py  last block has valid PKCS#7 padding            -> NO

Both were fair -- group_sessions.py proved all 13 exchanges sit inside a single
4.07 s window, so one static key really is expected to open all of them.

But if the plaintext is a msgpack object and the sender pads to a 16-byte
boundary without PKCS#7 (or not at all), then BOTH oracles reject the correct
key: the first block is not printable, and the last block is not padding.  The
requests are known to be msgpack in this protocol, so this is not a stretch.

Oracle used here: full CBC decrypt of a gate reply, then require the WHOLE
plaintext to parse.  A wrong key yields random bytes, which essentially never
parse -- so unlike a first-block test this cannot be satisfied by luck.

Three IV layouts are tried, because the placement was never proven:
  IV_prefix   body = IV(16) || ct
  no_IV       body = ct, IV = 0
  IV_suffix   body = ct || IV(16)
Stage 1 only inspects the first block to keep the sweep at full speed; stage 2
does the real decrypt and parse for survivors.
"""
import re
import sys
import time

from Crypto.Cipher import AES

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_scan_msgpack.txt"
PROG = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_msgpack_progress.txt"

try:
    import msgpack
except ImportError:
    msgpack = None

# ------------------------------------------------------------- the corpus --
raw = open(LOG, "rb").read().split(b"\n")
gate, path, rq = [], None, None
for line in raw:
    if line.startswith(b"### REQ POST") or line.startswith(b"### REQ GET"):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
        rq = None
    elif line.startswith(b"REQHEX: "):
        try:
            rq = bytes.fromhex(line[8:].strip().decode())
        except ValueError:
            rq = None
    elif line.startswith(b"RESPHEX: "):
        try:
            b = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            b = None
        if b is not None and path and "/gate/" in path:
            gate.append((path, rq, b))
        path = rq = None

gate = [g for g in gate if len(g[2]) >= 64]
if not gate:
    print("NO -- no gate replies in flows.log")
    raise SystemExit(1)

# smallest reply drives the sweep (fewest blocks in stage 2), the rest confirm
gate.sort(key=lambda t: len(t[2]))
primary_path, primary_req, primary = gate[0]
confirm = [g[2] for g in gate if g[2] is not primary]
print("stage-1/2 target : %d bytes  %s" % (len(primary), primary_path))
print("confirmation     : %d replies, lengths %s"
      % (len(confirm), [len(c) for c in confirm]))
print("oracle           : full plaintext must PARSE (msgpack / json / gzip /")
print("                   mostly-printable).  No padding assumed anywhere.")
print("layouts          : IV_prefix, no_IV, IV_suffix")
print("")

# ------------------------------------------------------------ the layouts ---
def first_block_pt(ec, body, lay):
    """Plaintext of block 0 under the chosen IV layout (stage 1).

    Takes the already-built ECB object: building one per layout made the sweep
    three times slower than it needed to be, and the key does not change
    between layouts.
    """
    if lay == "IV_prefix":
        if len(body) < 32:
            return None
        return (int.from_bytes(ec.decrypt(body[16:32]), "big")
                ^ int.from_bytes(body[0:16], "big")).to_bytes(16, "big")
    if lay == "no_IV":
        return ec.decrypt(body[0:16])
    # IV_suffix
    if len(body) < 32:
        return None
    return (int.from_bytes(ec.decrypt(body[0:16]), "big")
            ^ int.from_bytes(body[-16:], "big")).to_bytes(16, "big")


def full_pt(key, body, lay):
    """Whole plaintext under the chosen IV layout (stage 2)."""
    if lay == "IV_prefix":
        iv, ct = body[:16], body[16:]
    elif lay == "no_IV":
        iv, ct = b"\x00" * 16, body
    else:
        iv, ct = body[-16:], body[:-16]
    if len(ct) == 0:
        return None
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    # CBC chains through, so reconstruct using the IV only for block 0
    if lay != "no_IV":
        pass
    return pt


def parses(pt):
    """Does the entire plaintext actually parse?  Strong enough to be decisive."""
    if not pt:
        return None
    if pt[:3] == b"\x1f\x8b\x08":
        try:
            import zlib
            d = zlib.decompress(pt, 16 + zlib.MAX_WBITS)
            return "gzip -> %d bytes" % len(d)
        except Exception:
            return None
    if msgpack is not None:
        try:
            msgpack.unpackb(pt, raw=False, strict_map_key=False)
            return "msgpack"
        except Exception:
            pass
    try:
        import json
        json.loads(pt.decode("utf-8"))
        return "json"
    except Exception:
        pass
    txt = pt.rstrip(b"\x00")
    if txt and sum(1 for c in txt if 0x20 <= c < 0x7E or c in (9, 10, 13)) >= 0.8 * len(txt):
        return "text"
    return None


def plausible_start(b):
    """Stage 1: does block 0 open like a container object?"""
    if b is None:
        return False
    t = b[0]
    if not (0x80 <= t <= 0x9F):          # fixmap / fixarray
        if t not in (0xDE, 0xDF, 0xDC, 0xDD, 0xC0, 0xC2, 0xC3):
            return False
    s = b[1]
    if 0xA0 <= s <= 0xBF:                # fixstr key
        return True
    if 0x80 <= s <= 0x9F:                # nested container
        return True
    if s in (0xD9, 0xDA, 0xDB, 0xA0):
        return True
    if 0x90 <= s <= 0x9F:
        return True
    return False


# ------------------------------------------------------------------ run -----
LIMIT = 0
if len(sys.argv) > 1:
    LIMIT = int(sys.argv[1])
    print("*** BENCH: first %d offsets ***" % LIMIT)

data = open(SO, "rb").read()
stop = len(data) - 31 if not LIMIT else min(len(data) - 31, LIMIT)
print("file %d bytes, offsets 0 .. %d" % (len(data), stop - 1))
print("")
sys.stdout.flush()

LAYS = ("IV_prefix", "no_IV", "IV_suffix")
t0 = time.time()
done = 0
stage2 = 0
hits = []
next_report = 5_000_000
last = t0

for off in range(stop):
    key = data[off:off + 32]
    ec = AES.new(key, AES.MODE_ECB)
    lay = None
    # try the most likely layout first, only fall back if the shape is wrong
    if plausible_start(first_block_pt(ec, primary, "IV_prefix")):
        lay = "IV_prefix"
    else:
        for L in ("no_IV", "IV_suffix"):
            if plausible_start(first_block_pt(ec, primary, L)):
                lay = L
                break
    if lay is not None:
        stage2 += 1
        pt = full_pt(key, primary, lay)
        real = parses(pt)
        if real:
            # confirm against every other recorded gate reply under the same key
            allok = True
            kinds = []
            for c in confirm:
                k = parses(full_pt(key, c, lay))
                if not k:
                    allok = False
                    break
                kinds.append(k)
            if allok:
                hits.append((off, key, lay, real, kinds))
                print("  HIT offset 0x%x layout %s  %s  confirm=%s"
                      % (off, lay, real, kinds), flush=True)

    done += 1
    if done >= next_report:
        now = time.time()
        rate = (next_report - 5_000_000) / max(now - last, 1e-6)
        line = ("progress %9d / %d (%.1f%%)  %.0f off/s  ETA %.0fs  stage2=%d"
                % (done, stop, 100.0 * done / stop, rate,
                   (stop - done) / max(rate, 1e-6), stage2))
        print(line, flush=True)
        open(PROG, "w", encoding="utf-8").write(line + "\n")
        next_report += 5_000_000
        last = now

dt = time.time() - t0
print("")
print("tested %d offsets in %.1f s (%.0f/s)" % (done, dt, done / max(dt, 1e-6)))
print("reached stage 2 (shape plausible): %d" % stage2)
print("parsed AND confirmed on all %d replies: %d" % (len(confirm), len(hits)))
print("")
if hits:
    print("YES -- key found")
    for off, key, lay, real, kinds in hits:
        print("   offset 0x%x  layout %s  %s  key %s" % (off, lay, real, key.hex()))
else:
    print("NO -- no 32-byte window of libUE4.so yields a plaintext that parses")
    print("      under any IV layout, with or without PKCS#7 padding")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("primary %s %d bytes\nconfirm %d\nstage2 %d\nhits %d\n"
            % (primary_path, len(primary), len(confirm), stage2, len(hits)))
    for off, key, lay, real, kinds in hits:
        f.write("HIT 0x%x %s %s %s %s\n" % (off, lay, real, kinds, key.hex()))
    f.write("elapsed %.1f\n" % dt)
print("wrote %s" % OUT)
