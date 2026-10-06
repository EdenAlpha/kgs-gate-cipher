"""Session watcher: log run + phone state every 3 minutes for ~3.5 hours."""
import subprocess
import time

REPO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"


def sh(args):
    r = subprocess.run(args, cwd=REPO, capture_output=True, text=True)
    return (r.stdout.strip() + " " + r.stderr.strip()).strip()[:300]


for i in range(70):
    t = time.strftime("%H:%M:%S", time.gmtime())
    st = sh(["gh", "run", "view", "37376639368", "--json", "status",
             "--jq", ".status"])
    sh(["git", "fetch", "origin", "live-res-k"])
    sta = sh(["git", "show", "origin/live-res-k:status.txt"]).replace(
        "\n", "|")
    print("[%s] run=%s status=[%s]" % (t, st, sta), flush=True)
    if st not in ("in_progress", "queued", "waiting", ""):
        print("RUN ENDED: %s" % st, flush=True)
        break
    time.sleep(180)
