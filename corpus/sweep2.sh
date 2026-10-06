#!/usr/bin/env bash
# Minimal memory sweeper v2: same proven copy shape as the manual test that
# just returned 32 KB clean (result 1253). No prune, no markers, no cleverness:
# copy every writable region >= 64 KB, gzip, next cycle. find_key.py decides.
set -u
S=127.0.0.1:5555
PKG=jp.konami.pesam
# NOTE: this must stay /tmp/kgs/sweep. live_loop.sh's auto_find_key() scans
# exactly that path every 20 min and publishes the verdict to live-res. When
# this script wrote to a different directory the in-loop finder was blind to
# the real capture -- which is why no verdict ever appeared on its own, and
# why the runner dying took the only scan with it.
DIR=/tmp/kgs/sweep
mkdir -p "$DIR"
say() { echo "[sw2 $(date -u +%H:%M:%S)] $*"; }
n=0
while [ "$n" -lt 120 ]; do
  P=$(adb -s "$S" shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
  if [ -z "$P" ]; then sleep 5; continue; fi
  n=$((n + 1))
  d="$DIR/cycle$n"
  mkdir -p "$d"
  adb -s "$S" shell su 0 cat "/proc/$P/maps" 2>/dev/null | tr -d '\r' > "$d/maps"
  got=0
  while read -r range perms rest; do
    case "$perms" in *w*) ;; *) continue ;; esac
    s=${range%-*}; e=${range#*-}
    s=$((0x$s)); e=$((0x$e)); sz=$((e - s))
    if [ "$sz" -lt 65536 ]; then continue; fi
    skip=$((s / 4096)); count=$((sz / 4096))
    adb -s "$S" shell "su 0 sh -c \"dd if=/proc/$P/mem of=/data/local/tmp/w.bin bs=4096 skip=$skip count=$count\"" >/dev/null 2>&1 || continue
    adb -s "$S" pull /data/local/tmp/w.bin "$d/r_$s.bin" >/dev/null 2>&1 || continue
    adb -s "$S" shell rm -f /data/local/tmp/w.bin >/dev/null 2>&1 || true
    got=$((got + 1))
  done < "$d/maps"
  gzip -1 -f "$d"/r_*.bin 2>/dev/null || true
  kb=$(du -sk "$d" 2>/dev/null | cut -f1)
  say "cycle $n: $got regions ${kb:-0}KB"
done
say "sweeper done: $n cycles"
