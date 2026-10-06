"""Key-finder command: MATCH key=<hex> + opened body preview, or NO MATCH.

find_key.py is COMMITTED to main but was never deployed to the runner, so
this embeds it base64 -> /tmp/kgs/find_key.py first (same mechanism as the
sweeper: exact bytes, no network fetch that can 404 mid-run).

Prints its own verdict on separate labelled lines so neither outcome can be
mistaken for the other, and always prints the candidate counter (an honest
'9182 candidates tested' with NO MATCH is a real answer, a silent one is not).
"""
import base64
import sys

OUT = sys.argv[1]
SRC = sys.argv[2]
D = "/tmp/kgs"

raw = open(SRC, "rb").read()
if b"\r" in raw:
    print("warn: CRLF stripped from", SRC)
    raw = raw.replace(b"\r\n", b"\n")
b64 = base64.b64encode(raw).decode()
assert b"find_key" in raw or b"argparse" in raw, "SRC does not look like find_key.py"
print("src bytes:", len(raw))

parts = [
    "exec echo %s | base64 -d > %s/find_key.py" % (b64, D),
    "grep -q 'argparse' %s/find_key.py" % D,
    "echo ---INPUTS---",
    "echo SWEEP-DIRS:$(find %s/sweep -maxdepth 1 -type d -name 'c[0-9]*' | wc -l)" % D,
    "echo SWEEP-BYTES:$(du -sb %s/sweep | cut -f1)" % D,
    "echo FLOWS:$(grep -c '^### ' %s/flows.log)" % D,
    "echo ---RUN---",
    # `;` not `&&` after the finder: NO MATCH exits 2 by design, and the rc
    # must be PRINTED rather than silently aborting the chain. After `;`,
    # $? is still the finder's status, so FINDER-RC is honest either way.
    "python3 %s/find_key.py --dir %s/sweep --flows %s/flows.log"
    " ; echo FINDER-RC:$? ; echo ---END---" % (D, D, D),
]

line = " && ".join(parts[:-1]) + " && " + parts[-1]
assert "\n" not in line and "\r" not in line
open(OUT, "w", newline="\n").write(line)
print("cmd bytes:", len(line))
