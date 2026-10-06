"""Rebuild the sweeper-start payload without PowerShell mangling.

Queued cmd 502f55c runs bash /tmp/kgs/sweep_fixed.sh, but sweep_cmd.txt
deploys /tmp/kgs/sweep.sh -- the running command points at a file that is
not there, so no sweeper is starting. This rebuilds: kill any stray
sweeper, redeploy (idempotent), start, plus a 60s watcher that appends
progress to live.log so every heartbeat's live_tail.txt shows it (round
result posts vanish on this loop; the heartbeat tail is the visible
channel).
"""
import subprocess

REPO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
WT = r"C:\Users\Administrator\AppData\Local\Temp\2\wt-cmdk"

body = open("sweep_cmd.txt", "rb").read().replace(b"\r\n", b"\n").strip()
assert body.startswith(b"exec ")
body = body[len(b"exec "):]
assert b"\n" not in body and b"\r" not in body

watcher = (
    b"; (while true; do sleep 60; "
    b"echo SWEEP game=$(pidof jp.konami.pesam) "
    b"cycles=$(ls /tmp/kgs/sweep 2>/dev/null | wc -l) "
    b"kb=$(du -sk /tmp/kgs/sweep 2>/dev/null | cut -f1) "
    b">>/tmp/kgs/live.log; done &) ; "
    b"echo WATCHER_SET game=$(pidof jp.konami.pesam) >>/tmp/kgs/live.log"
)
payload = (b"exec pkill -f 'bash /tmp/kgs/sweep'; sleep 2; "
           + body + watcher + b"\n")

open("sweep_fix_cmd.txt", "wb").write(payload)
print("payload len:", len(payload))

r = subprocess.run(["python", "push_cmd.py", "sweep_fix_cmd.txt",
                    "lane k: FIX sweeper start (right path sweep.sh, kill strays, 60s live.log watcher)"],
                   capture_output=True, text=True)
print(r.stdout[-600:])
print(r.stderr[-300:])
