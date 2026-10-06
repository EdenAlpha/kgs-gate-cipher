"""Pull files from the runner to this machine over the relay's /dl endpoint.

The end-of-job artifact upload is not a safe route home: the hosted runner has
died mid-session three times, and each time step 06 never ran, so everything
in /tmp was lost -- a 341 MB memory sweep among it. This fetches over the
tunnel that already carries screenshots, so it only needs the runner to be
alive at the moment of the transfer.

Usage:  python pull_files.py out_dir [name ...]
        python pull_files.py out_dir --all
Resumes by requesting only the bytes a local file is missing.
"""
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
cfg = json.load(open(os.path.join(HERE, "relay.json")))
URL, TOK = cfg["url"], cfg["token"]
CHUNK = 8 * 1024 * 1024
RETRY = 4


def get(path, off=0, ln=CHUNK, raw=True, tries=RETRY, extra=None):
    # Build the query once, with a single '?'. Passing "/dl?path=x" as `path`
    # produced "/dl?path=x?token=...", so the relay parsed the token as part of
    # the filename and every request 403'd -- a client bug, not a relay one.
    params = ["token=%s" % TOK, "off=%d" % off, "len=%d" % ln]
    if extra:
        params.append(extra)
    url = "%s%s?%s" % (URL, path, "&".join(params))
    last = None
    for _ in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=180) as r:
                return r.read() if raw else r.read().decode("utf-8", "replace")
        except Exception as e:            # tunnel hiccup: retry, do not abort
            last = e
    raise last


def listing():
    txt = get("/ls", ln=4096, raw=False)
    out = []
    for line in txt.splitlines():
        if not line.strip():
            continue
        name, _, size = line.partition("\t")
        if size.isdigit() and int(size) > 0:
            out.append((name, int(size)))
    return out


def pull(name, size, out_dir):
    dst = os.path.join(out_dir, name)
    os.makedirs(out_dir, exist_ok=True)
    have = os.path.getsize(dst) if os.path.exists(dst) else 0
    if have == size:
        return name, size, "complete"
    with open(dst, "ab") as fh:
        while have < size:
            blob = get("/dl", off=have, ln=min(CHUNK, size - have),
                       extra="path=%s" % name)
            if not blob:
                break
            fh.write(blob)
            have += len(blob)
    return name, os.path.getsize(dst), "ok" if have == size else "SHORT"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    out_dir = sys.argv[1]
    want = sys.argv[2:]
    files = listing()
    if not files:
        print("nothing staged under /tmp/kgs/full yet")
        return 1
    if want == ["--all"] or not want:
        files = files
    else:
        files = [f for f in files if f[0] in want]
    for name, size in files:
        print("-> %-34s %10.1f MB" % (name, size / 1048576.0), flush=True)
    for name, size in files:
        n, got, st = pull(name, size, out_dir)
        print("   %-34s %10.1f MB  %s" % (n, got / 1048576.0, st), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())