"""Pull the exact recorded request headers for one gate call out of flows.mitm.

flows.mitm is mitmproxy's native serialization, so it is parsed as bytes: find
the 'pes-custom-encrypt' header key and print the window around it, plus the
same window around the first 'sign=' so the full Cookie/UA set is visible.
Output goes to a UTF-8 file because the console is cp1252.
"""
import re

MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\hdrs.txt"

d = open(MITM, "rb").read()
out = []


def emit(label, blob):
    out.append("=== %s ===" % label)
    # keep it printable so the file is diff-friendly
    out.append("".join(chr(c) if 32 <= c < 127 or c in (10, 13, 9) else "."
                       for c in blob))
    out.append("")


hits = list(re.finditer(rb"pes-custom-encrypt", d))
out.append("pes-custom-encrypt occurrences: %d" % len(hits))
for m in hits[:3]:
    emit("hdr @ %d" % m.start(), d[max(0, m.start() - 700):m.start() + 700])

shits = list(re.finditer(rb"sign=", d))
out.append("sign= occurrences: %d" % len(shits))
for m in shits[:2]:
    emit("sign @ %d" % m.start(), d[max(0, m.start() - 700):m.start() + 400])

ua = list(re.finditer(rb"User-Agent", d))
out.append("User-Agent occurrences: %d" % len(ua))
for m in ua[:3]:
    emit("ua @ %d" % m.start(), d[m.start():m.start() + 300])

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote", OUT, len("\n".join(out)), "chars")
