"""Dump the first gate bodies verbatim: path, size, first/last bytes, ASCII.

No oracle, no assumption -- just look at what is actually on the wire before
believing any framing theory.
"""
import re

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\peek_gate.txt"

recs, cur = [], None
for line in open(LOG, "r", encoding="utf-8", errors="replace"):
    line = line.rstrip("\n")
    m = re.match(r"### (REQ|RESP) POST (\S+)", line)
    if m:
        cur = {"kind": m.group(1), "path": m.group(2), "hdr": []}
        recs.append(cur)
        continue
    if cur is None:
        continue
    if line.startswith("REQHEX: "):
        cur["hex"] = line[8:].strip()
    elif line.startswith("RESPHEX: "):
        cur["hex"] = line[9:].strip()
    elif line.startswith("HDR: ") or line.startswith("H: "):
        cur["hdr"].append(line)

out = []
gate = [r for r in recs if "/gate/" in r["path"] and r.get("hex")]
out.append("gate records: %d" % len(gate))
out.append("gate paths  : %s" % sorted({r["path"] for r in gate}))
out.append("")

for r in gate[:6]:
    b = bytes.fromhex(r["hex"])
    out.append("-" * 78)
    out.append("%s %s  %d bytes" % (r["kind"], r["path"], len(b)))
    out.append("  first 48  %s" % b[:48].hex())
    out.append("  first 48A %s" % "".join(chr(x) if 32 <= x < 127 else "." for x in b[:48]))
    out.append("  last 24   %s" % b[-24:].hex())
    out.append("  mod8=%d mod16=%d distinct_bytes=%d" %
               (len(b) % 8, len(b) % 16, len(set(b))))
    for h in r["hdr"][:6]:
        out.append("  %s" % h[:200])

# is anything in the corpus ASCII / urlencoded / base64-looking?
ascii_n = sum(1 for r in gate
              if all(32 <= x < 127 for x in bytes.fromhex(r["hex"])[:64]))
out.append("")
out.append("bodies whose first 64 bytes are all printable: %d/%d" % (ascii_n, len(gate)))

# sizes and their relation to 8 and 16
sizes = sorted({len(bytes.fromhex(r["hex"])) for r in gate})
out.append("sizes: %s" % sizes)
out.append("all %%8==0 : %s" % all(s % 8 == 0 for s in sizes))
out.append("all %%16==0: %s" % all(s % 16 == 0 for s in sizes))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
