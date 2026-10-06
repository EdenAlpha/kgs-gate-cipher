"""Verification command: did the fixed sweeper capture BYTES in the new session?

Prints only numbers read off the device, so the answer is a printed byte
count or a printed pid -- never an assumption:

  NEW-SWEEPER   the fixed instance's cmdline (or empty = it died)
  GAMEPID       the relaunched game's pid
  CAPTURE       the sweeper's own 'starting capture' line (proves it saw pid)
  CYCLES        last cycle lines, each with its byte count
  SWEEP-DIR     total bytes on disk
  LATEST        newest cycle dir: file count + bytes actually pulled
  FLOWS         gate request/response lines for this login

Exit evidence is in the output itself; there is no branch that can print a
green result without those numbers being present.
"""
import sys

OUT = sys.argv[1]
D = "/tmp/kgs"
S = "adb -s 127.0.0.1:5555"

parts = [
    "exec echo ---SWEEPER---",
    "pgrep -af 'sweep_fixed' || echo NO-SWEEPER",
    "echo ---GAME---",
    "echo GAMEPID:$(%s shell pidof jp.konami.pesam | tr -d '\\r')" % S,
    "echo ---CAPTURE---",
    "grep 'starting capture' %s/sweep.log | tail -2 || echo NO-CAPTURE-LINE" % D,
    "echo ---CYCLES---",
    "grep 'cycle ' %s/sweep.log | tail -5 || echo NO-CYCLE-LINE" % D,
    "echo ---DISK---",
    "du -sh %s/sweep" % D,
    "echo ---LATEST---",
    "d=$(find %s/sweep -maxdepth 1 -type d -name 'c[0-9]*' | sort | tail -1)" % D,
    "echo NEWEST-DIR:$d",
    "echo PULLED-FILES:$(find $d -name 'r_*.bin' 2>/dev/null | wc -l)",
    "echo PULLED-BYTES:$(du -sb $d 2>/dev/null | cut -f1)",
    "echo TRUNCATED:$(wc -l < $d/truncated.log 2>/dev/null || echo 0)",
    # HAS_MARKERS is a flag FILE inside the cycle dir, not text to grep for
    "if [ -f $d/HAS_MARKERS ]; then echo FLAGGED:YES; cat $d/HAS_MARKERS;"
    " else echo FLAGGED:NO; fi",
    "echo ---FLOWS---",
    "grep -c '^### ' %s/flows.log" % D,
]

line = " && ".join(parts[1:])
line = parts[0] + " && " + line
assert "\n" not in line and "\r" not in line
open(OUT, "w", newline="\n").write(line)
print("cmd bytes:", len(line))
