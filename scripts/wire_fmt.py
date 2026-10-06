"""Is any recorded body gzip on the wire, and what sizes do we actually see?

Answers two questions that decide the next move:

  Q1  Do any captured message bodies start with the gzip magic 1f 8b?
      If yes, the payload is compressed before/without encryption and the
      key test should decrypt-then-gzip. If no, gzip is inside the cipher
      and a wrong key will never gunzip.
  Q2  What body sizes appear, and does Content-Length agree?
"""
import re

D = open(r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm", "rb").read()

n = 0
gz = 0
sizes = {}
for m in re.finditer(rb"7:content;(\d+):", D):
    L = int(m.group(1))
    e = m.end()
    if e + L > len(D):
        continue
    body = D[e:e + L]
    sizes[L] = sizes.get(L, 0) + 1
    n += 1
    if body[:2] == b"\x1f\x8b":
        gz += 1
        if gz <= 5:
            print("GZIP content len=%d at %s head=%s" % (L, hex(m.start()), body[:8].hex()))

print("content blocks: %d   gzip-magic among them: %d" % (n, gz))
print("distinct sizes: %d" % len(sizes))
print("smallest sizes:", sorted(sizes.items())[:15])
print("largest sizes:", sorted(sizes.items())[-10:])
print("gzip magic anywhere in file:", len(re.findall(re.escape(b"\x1f\x8b"), D)))
print("msgpack-ish first-byte histogram for content blocks:")
hist = {}
for m in re.finditer(rb"7:content;(\d+):", D):
    L = int(m.group(1))
    e = m.end()
    if e + L > len(D):
        continue
    b0 = D[e]
    hist[b0] = hist.get(b0, 0) + 1
top = sorted(hist.items(), key=lambda kv: -kv[1])[:12]
print([(hex(k), v) for k, v in top])
