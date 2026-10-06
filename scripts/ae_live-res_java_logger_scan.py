"""java_logger_scan.py -- does the Java side write to android.util.Log?

libUE4.so exports Java_jp_konami_Logger_PrintNative, so a Java class
jp.konami.Logger exists with a native method.  If that class (or Konami's
other classes) calls android.util.Log, logcat gets output regardless of what
the native sink pointer does.

Scans the jadx output for:
  - the Logger class itself
  - every use of android.util.Log under jp/konami
  - printNative / PrintNative call sites
"""
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(__file__))
CAND = [os.path.join(ROOT, "jadx_out", "sources"),
        os.path.join(ROOT, "efootball-apk", "jadx_out", "sources"),
        os.path.join(ROOT, "apkJadx", "sources")]
SRC = None
for c in CAND:
    if os.path.isdir(c):
        SRC = c
        break

if SRC is None:
    # walk down from root looking for a dir named sources containing jp/konami
    for dirpath, dirnames, filenames in os.walk(ROOT):
        if os.path.isdir(os.path.join(dirpath, "jp", "konami")):
            SRC = dirpath
            break

if SRC is None or not os.path.isdir(os.path.join(SRC, "jp", "konami")):
    print("could not locate jadx sources/jp/konami")
    for c in CAND:
        print("  tried:", c, os.path.isdir(c))
    sys.exit(1)

print("jadx sources root: %s" % SRC)
KON = os.path.join(SRC, "jp", "konami")

files = []
for dp, dn, fn in os.walk(KON):
    for f in fn:
        if f.endswith(".java"):
            files.append(os.path.join(dp, f))
print("java files under jp/konami: %d" % len(files))

print()
print("=" * 78)
print("the Logger class")
print("=" * 78)
for p in files:
    if os.path.basename(p) == "Logger.java":
        print("  found: %s" % p)
        print(open(p, encoding="utf-8", errors="replace").read()[:6000])

print()
print("=" * 78)
print("jp/konami files that use android.util.Log")
print("=" * 78)
USE = re.compile(r"\bandroid\.util\.Log\b|\bLog\.(v|d|i|w|e|wtf)\s*\(")
hits = []
for p in files:
    try:
        t = open(p, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    if "import android.util.Log" in t or USE.search(t):
        hits.append(p)
print("  %d file(s)" % len(hits))
for p in hits[:40]:
    print("   ", os.path.relpath(p, SRC))

print()
print("=" * 78)
print("printNative / PrintNative call sites anywhere in jp/konami")
print("=" * 78)
n = 0
for p in files:
    try:
        t = open(p, encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    for m in re.finditer(r".*\b[Pp]rintNative\b.*", t):
        print("   %s: %s" % (os.path.basename(p), m.group(0).strip()[:160]))
        n += 1
print("  %d occurrence(s)" % n)

print()
print("=" * 78)
print("whole-jadx scan: files importing android.util.Log (top-level counts)")
print("=" * 78)
cnt = {}
for dp, dn, fn in os.walk(os.path.dirname(SRC)):
    for f in fn:
        if not f.endswith(".java"):
            continue
        p = os.path.join(dp, f)
        try:
            t = open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        if "import android.util.Log;" in t:
            pkg = os.path.relpath(p, SRC).replace(os.sep, "/").split("/")[0]
            cnt[pkg] = cnt.get(pkg, 0) + 1
for k, v in sorted(cnt.items(), key=lambda kv: -kv[1])[:30]:
    print("   %-40s %d" % (k, v))
