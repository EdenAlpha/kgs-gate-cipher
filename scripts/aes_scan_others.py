"""Is the AES key somewhere OTHER than libUE4.so, and is it really 32 bytes?

Established so far:
  * the bodies are genuine ciphertext (uniform entropy, re-randomised per
    request, all lengths %16==0) -- so there IS a key
  * 160,822,937 offsets of libUE4.so fail PKCS#7 validation on every recorded
    reply, under two independent oracles (printable, then padding)

So either the key lives in another file, or it is not 32 bytes long.  The
header literally says "AES256", but a header label is not proof of key size,
so 16-byte and 24-byte keys are tested alongside 32.

Sources are every uncompressed byte stream we actually hold: the three dex
files, every decompressed entry of every apk (skipping libUE4.so, already
done), blob.bin, and the two big asset packs are deferred -- they are 780 MB
and would cost hours before anything else was ruled in or out.

Same oracle as the validated scan: PKCS#7 pad must hold on EVERY recorded gate
reply, which is content-agnostic and worth ~1e-13 false positives.
"""
import glob
import os
import zipfile

from Crypto.Cipher import AES

GAME = r"C:\Users\Administrator\AppData\Local\Temp\2\game"
LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_scan_others.txt"
PROG = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_others_progress.txt"

import re
import sys
import time

raw = open(LOG, "rb").read().split(b"\n")
gate, path = [], None
for line in raw:
    if line.startswith(b"### RESP ") or line.startswith(b"### REQ "):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
    elif line.startswith(b"RESPHEX: "):
        try:
            b = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            b = None
        if b is not None and path and "/gate/" in path:
            gate.append(b)
        path = None

gate.sort(key=len, reverse=True)
targets = [b for b in gate if len(b) >= 64][:6]
print("gate replies: %d   confirming on %d, lengths %s"
      % (len(gate), len(targets), [len(t) for t in targets]))
sys.stdout.flush()

EXCLUDE = {"lib/arm64-v8a/libUE4.so"}
# the two asset packs are ~780 MB each; defer them
DEFER = ("split_pad_it_0.apk", "split_pad_it_1.apk")


def pad_ok(block):
    n = block[15]
    return 1 <= n <= 16 and block[16 - n:] == bytes([n]) * n


def xor16(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")


def build_sources():
    srcs = []
    for p in sorted(glob.glob(GAME + r"\*.dex")):
        srcs.append((os.path.basename(p), open(p, "rb").read()))
    p = GAME + r"\blob.bin"
    if os.path.exists(p):
        srcs.append(("blob.bin", open(p, "rb").read()))
    for p in sorted(glob.glob(GAME + r"\*.apk")):
        nm = os.path.basename(p)
        if nm in DEFER:
            continue
        try:
            z = zipfile.ZipFile(p)
        except Exception:
            continue
        for i in z.infolist():
            if i.is_dir() or i.filename in EXCLUDE:
                continue
            if i.file_size == 0 or i.file_size > 60_000_000:
                continue
            try:
                data = z.read(i)
            except Exception:
                continue
            if len(data) >= 64:
                srcs.append(("%s!%s" % (nm, i.filename), data))
        z.close()
    return srcs


def opens(key, ec, bodies, kl_layout_cache=None):
    """Return the layout under which every body ends in valid PKCS#7, else None."""
    for lay in (1, 2):
        ok = True
        for r in bodies:
            if lay == 1:
                if len(r) < 48:
                    ok = False
                    break
                prev, last = r[-32:-16], r[-16:]
            else:
                if len(r) < 64:
                    ok = False
                    break
                prev, last = r[-48:-32], r[-32:-16]
            if not pad_ok(xor16(ec.decrypt(last), prev)):
                ok = False
                break
        if ok:
            return lay
    return None


srcs = build_sources()
total = sum(len(d) for _, d in srcs)
print("sources: %d   total %d bytes" % (len(srcs), total))
for nm, d in srcs:
    print("   %9d  %s" % (len(d), nm))
print("key lengths: 32, 24, 16")
print("")
sys.stdout.flush()

KEYLENS = (32, 24, 16)
t0 = time.time()
done = 0
hits = []
next_report = 20_000_000

for nm, data in srcs:
    for kl in KEYLENS:
        stop = len(data) - kl + 1
        for off in range(stop):
            key = data[off:off + kl]
            ec = AES.new(key, AES.MODE_ECB)
            # fast reject on one reply, one block, either layout
            r = targets[0]
            fast = False
            for prev, last in ((r[-32:-16], r[-16:]), (r[-48:-32], r[-32:-16])):
                if pad_ok(xor16(ec.decrypt(last), prev)):
                    fast = True
                    break
            if fast:
                lay = opens(key, ec, targets)
                if lay:
                    hits.append((nm, off, kl, key, lay))
                    print("  HIT %s off=%d keylen=%d layout=%d key=%s"
                          % (nm, off, kl, lay, key.hex()), flush=True)
            done += 1
            if done >= next_report:
                now = time.time()
                rate = (next_report - 20_000_000) / max(now - t0, 1e-6)
                line = ("progress %10d / %d (%.1f%%)  %.0f off/s  %s"
                        % (done, total * 3, 100.0 * done / (total * 3),
                           max(rate, 1), nm))
                print(line, flush=True)
                open(PROG, "w", encoding="utf-8").write(line + "\n")
                next_report += 20_000_000

dt = time.time() - t0
print("")
print("tested %d key/offset combinations in %.1f s" % (done, dt))
print("hits: %d" % len(hits))
if not hits:
    print("NO -- no key of 16, 24 or 32 bytes in any non-libUE4 file opens "
          "every recorded gate reply")
else:
    for nm, off, kl, key, lay in hits:
        print("YES %s off 0x%x len %d layout %d %s" % (nm, off, kl, lay, key.hex()))

open(OUT, "w", encoding="utf-8").write(
    "\n".join(["sources: %d  total %d bytes" % (len(srcs), total)] +
              ["%9d  %s" % (len(d), n) for n, d in srcs] + ["", "hits: %d" % len(hits)] +
              ["%s off=0x%x len=%d layout=%d %s" % (n, o, k, l, ky.hex())
               for n, o, k, ky, l in hits] +
              ["", "completed in %.1f s" % dt]))
print("wrote %s" % OUT)
