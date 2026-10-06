"""logcat_scan.py -- can adb logcat show the final score?

Three things decide it:
  A. does libUE4.so import Android's logging functions at all?
     (if it never calls liblog, logcat will contain nothing from the game)
  B. does it carry UE4 log categories / LOG_TAG strings (UE_LOG maps to
     __android_log_print with the category as the tag on Android)?
  C. are there format strings that would print a score, result or
     full/half-time event?

Prints exact counts; absence is reported as absence, not as proof.
"""
import os
import struct
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "efootball-apk", "native", "lib", "arm64-v8a",
                   "libUE4.so")
STRDUMP = os.path.join(HERE, "efootball-apk", "ue4_strings.txt")

data = open(LIB, "rb").read()


# ---------------------------------------------------------------- ELF sections
def sections(d):
    if d[:4] != b"\x7fELF":
        return {}
    e_shoff = struct.unpack_from("<Q", d, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 58)
    if e_shoff == 0 or e_shnum == 0:
        return {}
    sho = e_shoff + e_shstrndx * e_shentsize
    str_off = struct.unpack_from("<Q", d, sho + 24)[0]
    str_size = struct.unpack_from("<Q", d, sho + 32)[0]
    strtab = d[str_off:str_off + str_size]
    out = {}
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", d, o)[0]
        sh_type = struct.unpack_from("<I", d, o + 4)[0]
        sh_offset = struct.unpack_from("<Q", d, o + 24)[0]
        sh_size = struct.unpack_from("<Q", d, o + 32)[0]
        end = strtab.find(b"\x00", name_off)
        nm = strtab[name_off:end].decode("ascii", "replace")
        out[nm] = (sh_type, sh_offset, sh_size)
    return out


SEC = sections(data)
print("=" * 78)
print("ELF sections found: %d" % len(SEC))
for want in (".dynstr", ".dynsym", ".strtab", ".symtab", ".rodata"):
    if want in SEC:
        t, o, s = SEC[want]
        print("   %-10s type=%-3d off=%-10d size=%d" % (want, t, o, s))
    else:
        print("   %-10s ABSENT" % want)

# --------------------------------------------------------------- A. log imports
print()
print("=" * 78)
print("A. Android logging imports (from .dynstr)")
print("=" * 78)
NEEDLES = [
    "__android_log_print", "__android_log_write", "__android_log_assert",
    "__android_log_is_loggable", "__android_log_set_logger",
    "__android_log_set_default_tag", "android_logger_list_open",
    "logcat", "liblog", "ALOG", "android/log.h",
]
if ".dynstr" in SEC:
    _, o, s = SEC[".dynstr"]
    dynstr = data[o:o + s]
    names = [x for x in dynstr.split(b"\x00") if x]
    print("  .dynstr entries: %d" % len(names))
    hit_any = False
    for n in NEEDLES:
        hits = [x.decode("ascii", "replace") for x in names
                if n.encode() in x]
        if hits:
            hit_any = True
            print("    HIT  %-34s -> %s" % (n, hits[:5]))
    if not hit_any:
        print("  ZERO android-log symbols imported (.dynstr)")
    # anything log-ish at all
    logish = sorted({x.decode("ascii", "replace") for x in names
                     if b"log" in x.lower() and len(x) < 60})
    print("  .dynstr symbols containing 'log': %d" % len(logish))
    for x in logish[:40]:
        print("      ", x)
else:
    print("  no .dynstr section (fully static / stripped)")

print()
print("  raw-byte presence across the whole library (weak evidence):")
for n in NEEDLES[:8]:
    print("    %-34s %d" % (n, data.count(n.encode())))

# ------------------------------------------- B. UE4 log categories / LOG_TAG
print()
print("=" * 78)
print("B. UE4 log categories and tags (UE_LOG becomes __android_log_print)")
print("=" * 78)
blob = open(STRDUMP, encoding="utf-8", errors="replace").read()

CATS = ["LogTemp", "LogNet", "LogOnline", "LogOnlineSession", "LogSockets",
        "LogHttp", "LogSSL", "LogCertificate", "LogSecurity", "LogVoice",
        "LogBeacon", "LogNat", "LogPkt", "LogPKM", "LogPES", "LogKonami",
        "LogMatch", "LogWatchdog", "LogPun", "LogGame", "LogSpectator",
        "LogOnlineGame", "LogGoogleAnalytics", "LogHttpCache",
        "LogJson", "LogCore", "LogInit", "LogExit", "LogConfig"]
for c in CATS:
    n = blob.count(c)
    if n:
        i = blob.find(c)
        print("  HIT  %-24s x%-4d  ...%s..."
              % (c, n, re.sub(r"\s+", " ", blob[max(0, i - 60):i + 80])))
missing = [c for c in CATS if blob.count(c) == 0]
if missing:
    print("  absent: %s" % ", ".join(missing))

# generic category-shaped identifiers: Log followed by an uppercase word
cats = sorted(set(re.findall(r"\bLog[A-Z][A-Za-z0-9]{2,28}\b", blob)))
print()
print("  distinct 'Log<Word>' identifiers in libUE4.so: %d" % len(cats))
for c in cats[:60]:
    print("     ", c)

print()
print("  LOG_TAG / __android_log format-ish strings:")
for n in ["LOG_TAG", "%s/%s: ", "AndroidLog", "Android: ", "UE_LOG",
          "Log to file", "log file", "verbose log"]:
    print("    %-24s %d" % (n, blob.count(n)))

# ------------------------------------------------------------- C. score strings
print()
print("=" * 78)
print("C. strings that would print a score / result / full time")
print("=" * 78)
PATTERNS = [
    r"score[^\n]{0,60}", r"Score[^\n]{0,60}", r"full[ -]?time[^\n]{0,60}",
    r"FullTime[^\n]{0,60}", r"half[ -]?time[^\n]{0,60}",
    r"final ?result[^\n]{0,60}", r"kickoff[^\n]{0,50}",
    r"GOAL[^\n]{0,50}",
]
for pat in PATTERNS:
    hits = set(m.group(0) for m in re.finditer(pat, blob))
    hits = {h for h in hits if len(h.strip()) > 4}
    print("\n  /%s/  -> %d distinct" % (pat, len(hits)))
    for h in sorted(hits)[:12]:
        print("      ", h.strip()[:110])

# printf formats mentioning score-ish words
print()
print("=" * 78)
print("D. printf/UE_LOG-style formats containing score words")
print("=" * 78)
fmts = set(re.findall(r"[^\"\\\x00]{0,60}%[-+ #0-9.*hljztL]*[diuoxXfFgGeEsScp][^\"\\\x00]{0,60}", blob))
fmts = {f for f in fmts if re.search(r"score|goal|time|result|match", f, re.I)}
print("  candidates: %d" % len(fmts))
for f in sorted(fmts)[:40]:
    print("     ", f.strip()[:120])
