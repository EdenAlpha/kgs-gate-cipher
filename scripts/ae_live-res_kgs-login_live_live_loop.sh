#!/usr/bin/env bash
# Live control loop: lets a human drive the phone in near-real-time.
#
# Why this exists instead of a tunnel: GitHub runners accept no inbound
# connections, so adb cannot be reached from outside. Instead the two sides
# rendezvous through two branches that never conflict, because each side only
# ever WRITES one of them:
#
#   live-cmd  operator -> runner   (a single file, cmd.txt, one command)
#   live-res  runner   -> operator (screenshots, dumps, logs)
#
# A round trip takes 30-60 seconds: slow enough to feel deliberate, fast
# enough to tap through a setup screen in minutes instead of blind runs.
#
# Commands (one per line in live-cmd/cmd.txt, first line wins):
#   tap X Y            touch the screen there, then screenshot
#   taps X1 Y1 X2 Y2.. several touches in one round trip, then screenshot
#   wait N             sleep N seconds, then screenshot (downloads, long screens)
#   shot [name]        screenshot only
#   uidump             full clickable-node dump (geometry for aiming)
#   uitap REGEX        tap by node text (native UI; Compose hides text)
#   amstart COMP       am start -W -n COMP (launch an activity)
#   intent URI         am start -a VIEW -d URI
#   exec SH...         run shell on the host (proxy, CA, dumps -- logged verbatim)
#   flows [N]          tail N lines of the decrypted-flows log
#   status             heartbeat on demand
#   quit               end the session (falls through to publish/upload)
#
# Results go to live-res/results/NNN/ (out.txt + shot.png + ui.xml).
# live-res/status.txt is a heartbeat; live_tail.txt carries this script's own
# output so a crash is visible from outside instead of only at job end.
#
# LOUD FAILURE IS THE POINT: a silent push failure here once cost a whole
# multi-hour session, because the loop spun happily with a broken results dir
# and nothing looked wrong until the job ended. So every push is retried, the
# very first one is a probe that aborts the step on failure, and a watchdog
# aborts if nothing has been published for PUSH_WATCHDOG_SECS.
set -uo pipefail

CONTAINER="${CONTAINER:-redroid}"
: "${W:=/tmp/kgs}"
: "${LIVE_RES_DIR:=/tmp/live-res}"
: "${POLL_SECS:=8}"
: "${HEARTBEAT_EVERY:=15}"
: "${MAX_ROUNDS:=1400}"
: "${PUSH_WATCHDOG_SECS:=600}"
BRANCH=live-res

say() { echo "live: $*"; }
now() { date -u +%s; }

shot_to() { # $1 = dest png path on host
  sudo docker exec "$CONTAINER" sh -c \
    'screencap -p /data/local/tmp/live_shot.png' >/dev/null 2>&1
  sudo docker cp "$CONTAINER:/data/local/tmp/live_shot.png" "$1" \
    2>/dev/null || true
}

game_alive() {
  sudo docker exec "$CONTAINER" sh -c \
    'pidof jp.konami.pesam 2>/dev/null' 2>/dev/null | tr -d '\r' | awk '{print $1}'
}

flows_seen() { { grep -c '^### ' "$W/flows.log" 2>/dev/null || echo 0; } | head -1; }

LAST_PUSH=0

push_res() { # commit + push whatever is staged in LIVE_RES_DIR
  local label="$1" attempt
  if [ ! -e "$LIVE_RES_DIR/.git" ]; then
    echo "live: FATAL no git repo at $LIVE_RES_DIR -- cannot publish results"
    return 2
  fi
  cd "$LIVE_RES_DIR" || return 2
  for attempt in 1 2 3; do
    timeout 60 git add -A >/dev/null 2>&1
    if timeout 60 git diff --cached --quiet >/dev/null 2>&1; then
      cd - >/dev/null 2>&1 || true
      return 0                      # nothing new: success, but not a push
    fi
    if timeout 60 git -c user.name="live-bot" \
           -c user.email="live-bot@users.noreply.github.com" \
           commit -qm "live: $label" >/dev/null 2>&1; then
      # EVERY git call is time-boxed. An unbounded `git push` on a machine
      # that wants a credential prompt hangs forever, and a hung loop looks
      # exactly like a slow one from the outside.
      if timeout 120 git push origin "HEAD:refs/heads/$BRANCH" 2>&1 | tail -2; then
        LAST_PUSH=$(now)
        cd - >/dev/null 2>&1 || true
        return 0
      fi
    fi
    echo "live: push attempt $attempt failed for [$label]; rebasing onto $BRANCH"
    timeout 120 git fetch origin "$BRANCH" >/dev/null 2>&1 || true
    timeout 60 git rebase "origin/$BRANCH" >/dev/null 2>&1 || \
      timeout 60 git reset --hard "origin/$BRANCH" >/dev/null 2>&1 || true
    sleep 3
  done
  cd - >/dev/null 2>&1 || true
  echo "live: PUSH FAILED after 3 attempts [$label]"
  return 1
}

heartbeat() {
  local alive flows
  alive=$(game_alive); flows=$(flows_seen)
  { echo "time=$(date -u +%H:%M:%S)";
    echo "gamepid=${alive:-none}";
    echo "flows=$flows";
    echo "round=$1"; } > "$LIVE_RES_DIR/status.txt"
  # Publish this script's own output too: Actions only serves a step's log
  # after the step ends, so without this a crash is invisible for hours.
  tail -c 2000 "$W/live.log" 2>/dev/null > "$LIVE_RES_DIR/live_tail.txt" || true
  push_res "heartbeat $1"
}

probe() { # prove publishing works BEFORE waiting for a human
  mkdir -p "$LIVE_RES_DIR"
  echo "probe $(date -u +%H:%M:%S)" > "$LIVE_RES_DIR/status.txt"
  if ! push_res "probe"; then
    say "PROBE FAILED -- results cannot be published, aborting so logs come back"
    return 1
  fi
  say "probe published OK; live-res is live"
  return 0
}

run_cmd() { # $1 = round dir, $2... = command words
  local dir="$1"; shift
  local verb="$1"; shift || true
  local out="$dir/out.txt"
  local x y
  { echo "cmd: $verb $*"; echo "at: $(date -u +%H:%M:%S)"; } > "$out"
  case "$verb" in
    tap)
      sudo docker exec "$CONTAINER" /system/bin/input tap "$1" "$2" \
        >/dev/null 2>&1
      echo "tapped ($1,$2)" >> "$out"
      shot_to "$dir/shot.png"
      ;;
    taps)
      while [ $# -ge 2 ]; do
        x="$1"; y="$2"; shift 2
        echo "tap ($x,$y) at $(date -u +%H:%M:%S)" >> "$out"
        sudo docker exec "$CONTAINER" /system/bin/input tap "$x" "$y" \
          >/dev/null 2>&1
        sleep 2
      done
      shot_to "$dir/shot.png"
      ;;
    wait)
      sleep "${1:-60}"
      echo "waited ${1:-60}s" >> "$out"
      shot_to "$dir/shot.png"
      ;;
    shot)
      shot_to "$dir/shot.png"
      echo "screenshot only" >> "$out"
      ;;
    uidump)
      bash kgs-login/scripts/uidump.sh "$CONTAINER" "$dir/ui.xml" \
        >> "$out" 2>&1 || echo "uidump failed (see out)" >> "$out"
      shot_to "$dir/shot.png"
      ;;
    uitap)
      bash kgs-login/scripts/uitap.sh "$CONTAINER" "$1" >> "$out" 2>&1 \
        || echo "uitap missed" >> "$out"
      shot_to "$dir/shot.png"
      ;;
    amstart)
      sudo docker exec "$CONTAINER" sh -c "am start -W -n $1" \
        >> "$out" 2>&1
      sleep 5
      shot_to "$dir/shot.png"
      ;;
    intent)
      sudo docker exec "$CONTAINER" sh -c \
        "am start -a android.intent.action.VIEW -d '$1'" >> "$out" 2>&1
      sleep 5
      shot_to "$dir/shot.png"
      ;;
    exec)
      # shell on the HOST (proxy, CA, dumps). Logged verbatim for the audit.
      echo "\$ $*" >> "$out"
      eval "$*" >> "$out" 2>&1
      echo "rc=$?" >> "$out"
      ;;
    flows)
      tail -"${1:-40}" "$W/flows.log" >> "$out" 2>&1 \
        || echo "no flows.log yet" >> "$out"
      ;;
    status)
      echo "on demand heartbeat" >> "$out"
      ;;
    quit)
      echo "QUIT received" >> "$out"
      return 2
      ;;
    *)
      echo "UNKNOWN VERB: $verb" >> "$out"
      ;;
  esac
  { echo "gamepid: $(game_alive)";
    echo "flows: $(flows_seen)"; } >> "$out"
  return 0
}

main() {
  mkdir -p "$W" "$LIVE_RES_DIR"
  say "live control loop starting (poll ${POLL_SECS}s, max ${MAX_ROUNDS} rounds)"
  say "write commands to live-cmd/cmd.txt ; read live-res/results + status.txt"
  local last="" round=0 since_hb=0 rc=0 prc=0
  # Start the watchdog clock NOW, not at the first successful push: the failure
  # that matters most is the one where nothing was EVER published, and a
  # watchdog keyed on the last push can never fire in exactly that case.
  LAST_PUSH=$(now)
  probe || return 3
  while [ "$round" -lt "$MAX_ROUNDS" ]; do
    round=$((round + 1))
    since_hb=$((since_hb + 1))
    timeout 60 git fetch origin live-cmd >/dev/null 2>&1 || true
    cmd=$(timeout 60 git show origin/live-cmd:cmd.txt 2>/dev/null | head -1 | tr -d '\r')
    if [ -n "$cmd" ] && [ "$cmd" != "$last" ]; then
      last="$cmd"
      dir="$LIVE_RES_DIR/results/$(printf %04d "$round")"
      mkdir -p "$dir"
      # shellcheck disable=SC2086
      run_cmd "$dir" $cmd
      rc=$?
      push_res "round $round: $cmd"
      [ "$rc" = "2" ] && { say "quit received, ending loop"; break; }
      since_hb=0
    elif [ "$since_hb" -ge "$HEARTBEAT_EVERY" ]; then
      heartbeat "$round"
      since_hb=0
    fi
    # watchdog: if the operator has not been able to publish for 10 minutes,
    # something is broken and a 6-hour silent spin helps nobody
    if [ "$LAST_PUSH" -gt 0 ] && \
       [ $(( $(now) - LAST_PUSH )) -gt "$PUSH_WATCHDOG_SECS" ]; then
      say "WATCHDOG: nothing published for ${PUSH_WATCHDOG_SECS}s -- aborting"
      return 4
    fi
    sleep "$POLL_SECS"
  done
  heartbeat "end"
  say "loop ended after $round rounds"
  return 0
}

main
exit $?
