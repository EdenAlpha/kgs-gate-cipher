"""Is the libUE4.so on this machine the same file the sideloaded app runs?

The local copy was extracted at some point and its provenance was never
checked. This hashes the local file, then hashes lib/arm64-v8a/libUE4.so
inside every apk that was pulled off the device, and reports a byte-match
or a mismatch. It also reports whether more than one distinct build exists,
because two builds would invalidate every conclusion drawn so far.
"""
import hashlib
import os
import zipfile

GAME = r"C:\Users\Administrator\AppData\Local\Temp\2\game"
LOCAL = os.path.join(GAME, "libUE4.so")

local = open(LOCAL, "rb").read()
lh = hashlib.sha256(local).digest()
print("LOCAL libUE4.so  %d bytes  sha256=%s" % (len(local, ), lh.hex()))

found = []
for fn in sorted(os.listdir(GAME)):
    if not fn.endswith(".apk"):
        continue
    p = os.path.join(GAME, fn)
    try:
        z = zipfile.ZipFile(p)
    except Exception as e:
        print("  %-34s unreadable: %s" % (fn, e))
        continue
    names = [n for n in z.namelist() if n.endswith("libUE4.so")]
    if not names:
        continue
    for n in names:
        h = hashlib.sha256()
        size = 0
        with z.open(n) as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
                size += len(b)
        d = h.digest()
        same = "MATCH" if d == lh else "DIFFERENT"
        found.append((fn, n, size, d, same))
        print("  %-30s %-40s %12d %s" % (fn, n, size, same))

if not found:
    print("NO libUE4.so inside any pulled apk -- the local copy came from "
          "elsewhere, provenance UNKNOWN")
else:
    distinct = {d for _, _, _, d, _ in found}
    print("distinct builds among pulled apks: %d" % len(distinct))
    if any(s == "MATCH" for *_, s in found):
        print("YES: local copy byte-identical to the copy in the sideloaded apk")
    else:
        print("NO: local copy does NOT match any pulled apk")
