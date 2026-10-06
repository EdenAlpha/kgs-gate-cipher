#!/usr/bin/env bash
# Dump the full view hierarchy and list every tappable node with its center.
#
# Why this exists: Aurora 4.8 is Jetpack Compose, and its nodes expose NO text
# to `uiautomator dump` -- every text-aimed tap failed. But the dump still has
# class, resource-id, clickable and bounds for every node, which is enough to
# aim: this prints all clickable centers, and the screenshots show what each
# one is. Text failed; geometry works.
#
# Usage:  bash uidump.sh <container> [out-xml-path]
set -uo pipefail

CONTAINER="${1:?container required}"
OUT="${2:-/tmp/kgs/ui.xml}"

# NOTE: read the dump with `docker cp`, never `docker exec ... cat`. The
# exec-based read silently produced an EMPTY file every time (the error went
# to /dev/null), which is what made Aurora look like it was hiding its text
# from automation. It was hiding nothing -- we were reading nothing.
sudo docker exec "$CONTAINER" sh -c \
  'uiautomator dump /data/local/tmp/ui.xml' 2>&1 | tail -2
sudo docker cp "$CONTAINER:/data/local/tmp/ui.xml" "$OUT" 2>&1 \
  || { echo "UIDUMP: pull failed"; exit 1; }
[ -s "$OUT" ] || { echo "UIDUMP: dump is EMPTY (uiautomator produced nothing)"; exit 1; }

python3 - "$OUT" <<'PY'
import re, sys, html
xml = open(sys.argv[1], encoding="utf-8", errors="replace").read()
nodes = re.findall(r'<node [^>]*>', xml)
print("UIDUMP: %d nodes" % len(nodes))
n = 0
for tag in nodes:
    def attr(name):
        m = re.search(name + r'="([^"]*)"', tag)
        return html.unescape(m.group(1)) if m else ""
    clickable = attr("clickable") == "true"
    enabled = attr("enabled") == "true"
    cls = attr("class").split(".")[-1]
    rid = attr("resource-id").split("/")[-1]
    text = (attr("text") + " " + attr("content-desc")).strip()
    b = re.search(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", attr("bounds"))
    if not b:
        continue
    x1, y1, x2, y2 = map(int, b.groups())
    if x2 <= x1 or y2 <= y1:
        continue
    mark = "CLICK" if (clickable and enabled) else "-----"
    print("  %s  (%4d,%-4d)  %-18s %-28s %s"
          % (mark, (x1 + x2) // 2, (y1 + y2) // 2, cls[:18], rid[:28],
             text[:60]))
    if clickable and enabled:
        n += 1
print("UIDUMP: %d clickable" % n)
PY
