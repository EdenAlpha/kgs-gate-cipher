"""Decisive single command: liveness + the verdict, in one round.

Why one command: the captured memory lives on the RUNNER's /tmp and dies with
the job wall. There is no time for a probe round followed by a scan round, so
the liveness markers ride along with the scan -- if the loop wakes up at all,
this returns the verdict in the same round.

`timeout 1500` is a guard, not an expectation: a guarded scan still leaves
every progress line it printed in out.txt, so a truncated run is evidence
rather than silence.
"""
import base64
import sys

OUT = sys.argv[1]
SRC = sys.argv[2]
D = "/tmp/kgs"
S = "adb -s 127.0.0.1:5555"

raw = open(SRC, "rb").read()
if b"\r" in raw:
    print("warn: CRLF stripped")
    raw = raw.replace(b"\r\n", b"\n")
b64 = base64.b64encode(raw).decode()

line = (
    # deploy the crash-fixed finder
    "exec echo %s | base64 -d > %s/find_key.py" % (b64, D)
    + " && grep -q argparse %s/find_key.py" % D
    # liveness, free of charge in the same round
    + " && echo LIVENESS-$(date -u +%H:%M:%S)"
    + " && echo SWEEPER:$(pgrep -af sweep_fixed | tr '\\n' ' ')"
    + " && echo GAMEPID:$(%s shell pidof jp.konami.pesam | tr -d '\\r')" % S
    + " && echo DISK:$(du -sh %s/sweep | cut -f1)" % D
    + " && echo FLOWS:$(grep -c '^### ' %s/flows.log)" % D
    # the verdict
    + " && echo ---RUN---"
    + " && timeout 1500 python3 %s/find_key.py --dir %s/sweep"
      " --flows %s/flows.log" % (D, D, D)
    + " ; echo FINDER-RC:$? ; echo ---END---"
)
assert "\n" not in line and "\r" not in line
open(OUT, "w", newline="\n").write(line)
print("cmd bytes:", len(line))