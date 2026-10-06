import base64, sys

SRC = sys.argv[1]
OUT = sys.argv[2]
raw = open(SRC, "rb").read()
# git checks scripts out CRLF on Windows; the runner is Linux and a CRLF
# breaks every `case` on /proc fields (AGENTS.md). Normalize, don't refuse --
# refusing here just silently skips the round.
if b"\r" in raw:
    print("warn: CRLF stripped from", SRC)
    raw = raw.replace(b"\r\n", b"\n")
b64 = base64.b64encode(raw).decode()
# one line, no quotes inside that would survive word splitting differently
# the loop reads the FIRST word as the verb, so this must be `exec` -- the
# verb that evals the rest on the host (see live_loop.sh run_cmd).
# argv[3] == "bg" runs it detached: a foreground script would block the round
# and be killed with it, which would silently lose the whole capture.
base = SRC.replace("\\", "/").split("/")[-1]
if len(sys.argv) > 3 and sys.argv[3] == "bg":
    tail = " && nohup bash /tmp/kgs/`basename %s` > /tmp/kgs/%s.log 2>&1 &" % (base, base[:-3])
else:
    tail = " && bash /tmp/kgs/`basename %s`" % base
cmd = "exec echo %s | base64 -d > /tmp/kgs/`basename %s`%s" % (b64, base, tail)
assert "\n" not in cmd and "\r" not in cmd
open(OUT, "w", newline="\n").write(cmd)
print("cmd bytes:", len(cmd))
