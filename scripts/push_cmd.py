import os, shutil, subprocess, sys

REPO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects"
PAYLOAD = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Administrator\AppData\Local\Temp\2\relay_start_cmd.txt"
WT = r"C:\Users\Administrator\AppData\Local\Temp\2\wt-cmdk"
GIT = ["git", "-C", REPO]


def sh(args, cwd=REPO, check=True, quiet=False):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if not quiet:
        print("$", " ".join(args))
        if r.stdout.strip():
            print(r.stdout.strip()[:2000])
        if r.stderr.strip():
            print("ERR:", r.stderr.strip()[:800])
    if check and r.returncode != 0:
        sys.exit("FAILED: " + " ".join(args))
    return r


# clean up any stale worktree from an earlier attempt
sh(GIT + ["worktree", "prune"], quiet=True)
if os.path.isdir(WT):
    shutil.rmtree(WT, ignore_errors=True)

sh(GIT + ["fetch", "origin", "live-cmd-k"], quiet=True)
sh(GIT + ["worktree", "add", "--force", "-B", "live-cmd-k", WT, "origin/live-cmd-k"])

# single line, LF only
payload = open(PAYLOAD, "rb").read().replace(b"\r\n", b"\n").strip()
assert b"\r" not in payload and b"\n" not in payload
with open(os.path.join(WT, "cmd.txt"), "wb") as fh:
    fh.write(payload + b"\n")

sh(["git", "-C", WT, "add", "cmd.txt"])
sh(["git", "-C", WT, "-c", "user.name=live-bot",
    "-c", "user.email=live-bot@users.noreply.github.com",
    "commit", "-q", "-m",
    (sys.argv[2] if len(sys.argv) > 2 else
     "lane k: ID start relay plus tunnel (taps.log + /text)")])
sh(["git", "-C", WT, "push", "origin", "HEAD:refs/heads/live-cmd-k"])

# verify what is actually queued on the remote
r = sh(["git", "-C", WT, "show", "origin/live-cmd-k:cmd.txt"], quiet=True)
remote = r.stdout.splitlines()[0] if r.stdout else ""
local = payload.decode()
print("\nremote first line len:", len(remote), " local len:", len(local))
print("MATCH" if remote == local else "MISMATCH")

sh(GIT + ["worktree", "remove", WT, "--force"], quiet=True)
sh(GIT + ["worktree", "prune"], quiet=True)
print("worktree removed; working tree untouched")
