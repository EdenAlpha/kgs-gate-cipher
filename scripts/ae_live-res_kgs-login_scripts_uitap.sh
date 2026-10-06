#!/usr/bin/env bash
# Tap a UI element by its visible text. No coordinate guessing.
#
# Why this exists: every blind tap so far has missed something -- the center
# tap missed GOT IT for six minutes, and one blind tap visibly highlighted a
# button without pressing it. `uiautomator dump` gives the full view hierarchy
# with text and bounds, so a tap can aim at words instead of pixels.
#
# Usage:  bash uitap.sh <container> <text-regex>
# Prints TAP x y <text> on success. Exits 1 LOUDLY when uiautomator is missing
# or nothing matches -- a missed tap must never read as a successful one.
set -uo pipefail

CONTAINER="${1:?container required}"
PAT="${2:?pattern required}"

if ! sudo docker exec "$CONTAINER" sh -c 'command -v uiautomator' \
    >/dev/null 2>&1; then
  echo "UITAP: NO-UIAUTOMATOR on $CONTAINER"
  exit 1
fi
sudo docker exec "$CONTAINER" sh -c \
  'uiautomator dump /data/local/tmp/ui.xml' >/dev/null 2>&1 \
  || { echo "UITAP: dump failed"; exit 1; }

XML=$(sudo docker exec "$CONTAINER" cat /data/local/tmp/ui.xml 2>/dev/null)
MATCH=$(echo "$XML" | python3 -c "
import sys, re, html
xml = sys.stdin.read()
pat = re.compile(sys.argv[1])
best = None
for m in re.finditer(r'<node [^>]*>', xml):
    tag = m.group(0)
    def attr(n):
        mm = re.search(n + r'=\"([^\"]*)\"', tag)
        return html.unescape(mm.group(1)) if mm else ''
    text = (attr('text') + ' ' + attr('content-desc')).strip()
    if text and pat.search(text):
        b = re.search(r'bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]', tag)
        if b:
            x1, y1, x2, y2 = map(int, b.groups())
            if x2 > x1 and y2 > y1:
                best = ((x1 + x2) // 2, (y1 + y2) // 2, text)
                break
if best:
    print('%d %d %s' % best)
" "$PAT")

if [ -z "$MATCH" ]; then
  echo "UITAP: no match for [$PAT]"
  exit 1
fi
X=$(echo "$MATCH" | awk '{print $1}')
Y=$(echo "$MATCH" | awk '{print $2}')
TEXT=$(echo "$MATCH" | cut -d' ' -f3-)
sudo docker exec "$CONTAINER" /system/bin/input tap "$X" "$Y" >/dev/null 2>&1
echo "UITAP: tapped ($X,$Y) [$TEXT]"
