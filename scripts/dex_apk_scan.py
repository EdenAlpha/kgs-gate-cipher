"""Two things we have never looked at: the Java layer, and the other APKs.

So far every AES search has been inside libUE4.so, which turns out to have no
S-box and no AESE/AESD/AESMC instruction anywhere.  Two places the cipher could
be hiding that were never checked:

  1. the three classes*.dex files -- Android's javax.crypto does AES in the
     Java layer, which would leave no trace in native code at all
  2. base.apk / split_config.arm64_v8a.apk -- these are zip archives and may
     carry additional .so files beyond the single libUE4.so we pulled

Searches dex for the header literal, the known seed, and the usual Java cipher
transforms; lists every native library inside every apk.
"""
import re
import zipfile

GAME = r"C:\Users\Administrator\AppData\Local\Temp\2\game"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\dex_apk_scan.txt"

NEEDLES = [
    b"pes-custom-encrypt",
    b"Xrq-RtAF_91MAE82",
    b"AES/CBC/PKCS5Padding",
    b"AES/CBC/PKCS7Padding",
    b"AES/ECB/PKCS5Padding",
    b"AES/GCM/NoPadding",
    b"AES256",
    b"AES-256-CBC",
    b"javax.crypto",
    b"Cipher.getInstance",
    b"SecretKeySpec",
    b"pes22-game",
]

out = []


def say(s=""):
    out.append(str(s))


say("=" * 78)
say("1. DEX STRING TABLES")
say("=" * 78)
for name in ("classes.dex", "classes2.dex", "classes3.dex"):
    try:
        b = open(GAME + "\\" + name, "rb").read()
    except OSError as e:
        say("  %s : cannot read (%s)" % (name, e))
        continue
    say("")
    say("%s   %d bytes" % (name, len(b)))
    for nd in NEEDLES:
        n = b.count(nd)
        if n:
            say("    HIT  %-26s x%d" % (nd.decode(), n))
            # show surrounding printable run for context
            i = b.find(nd)
            lo = max(0, i - 60)
            ctx = b[lo:i + len(nd) + 60]
            ctx = bytes(c if 0x20 <= c < 0x7F else 0x2E for c in ctx)
            say("         ...%s..." % ctx.decode("ascii"))
    # any string that looks like a Java cipher transformation
    for m in set(re.findall(rb"AES[/\x2d][\x20-\x7e]{0,40}", b)):
        say("    transform-ish: %r" % m[:60])

say("")
say("=" * 78)
say("2. NATIVE LIBRARIES INSIDE EACH APK")
say("=" * 78)
for name in ("base.apk", "split_config.arm64_v8a.apk", "split_gpdeku.apk",
             "split_pad_it_0.apk", "split_pad_it_1.apk",
             "split_gpdeku.config.arm64_v8a.apk",
             "split_config.en.apk", "split_config.xhdpi.apk"):
    p = GAME + "\\" + name
    try:
        z = zipfile.ZipFile(p)
    except Exception as e:
        say("  %-36s : %s" % (name, e))
        continue
    say("")
    say("%s   (%d entries)" % (name, len(z.namelist())))
    so = [i for i in z.infolist()
          if i.filename.endswith(".so") or "/lib/" in i.filename]
    if so:
        for i in so:
            say("    %8d  %s" % (i.file_size, i.filename))
    else:
        # show what is in there instead, top-level only
        tops = sorted({n.split("/")[0] for n in z.namelist()})
        say("    no .so; top-level: %s" % ", ".join(tops[:12]))
    z.close()

say("")
say("=" * 78)
say("3. ANY .so IN THE ARCHIVES' LIB PATHS (all apks)")
say("=" * 78)
import glob
seen = set()
for p in glob.glob(GAME + r"\*.apk"):
    try:
        z = zipfile.ZipFile(p)
    except Exception:
        continue
    for n in z.namelist():
        if n.endswith(".so") and n not in seen:
            seen.add(n)
            say("  %-36s : %s" % (p.split("\\")[-1], n))
    z.close()
if not seen:
    say("  none -- libUE4.so is the only native library anywhere")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
