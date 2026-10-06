"""Build the one-line restart: retire the broken sweeper, force-stop the
game, start the FIXED sweeper, then relaunch the game.

Order is the whole point and every step prints proof:

  1. write the fixed script to /tmp/kgs/sweep_fixed.sh -- a NEW path, because
     overwriting /tmp/kgs/sweep.sh while the old bash may still be reading it
     can corrupt the running instance.
  2. touch STOP -> the old sweeper ends at its next loop top (its cycles are
     ~0s, so this is fast), then pkill as a backstop. pkill -f '/tmp/kgs/sweep.sh'
     matches only the old one: sweep_fixed.sh does not contain that substring,
     and live_loop's own cmdline is `bash live_loop.sh`.
  3. rm STOP BEFORE the new sweeper starts, or it exits on line 1 immediately.
  4. force-stop the game while no sweeper is watching, so no instance sees an
     empty pid and quits.
  5. start the fixed sweeper -- it waits for the pid.
  6. am start -W LAST, so cycle 1 of the new sweeper covers the fresh login
     from the very first frame.

`&` binds only to the nohup list because a `;` precedes it, so steps 1-4 run
synchronously before step 5, and `sleep 5 && am start` runs after step 5.
"""
import base64
import sys

SRC = sys.argv[1]
OUT = sys.argv[2]

raw = open(SRC, "rb").read()
# git checks scripts out CRLF on Windows; a CRLF breaks every `case` on
# /proc fields (AGENTS.md). Normalize, don't refuse.
if b"\r" in raw:
    print("warn: CRLF stripped from", SRC)
    raw = raw.replace(b"\r\n", b"\n")
b64 = base64.b64encode(raw).decode()
assert b"#!/usr/bin/env bash" in raw, "SRC does not look like sweep.sh"
assert b'A shell "su 0 sh -c \\"dd' in raw, "dd quoting fix is MISSING from SRC"
print("src bytes:", len(raw), "b64 bytes:", len(b64))

D = "/tmp/kgs"
S = "adb -s 127.0.0.1:5555"

# EVERY step is &&-gated so a bad decode aborts BEFORE the game is killed:
# with `;` joining the groups, a failed base64 decode would still have
# force-stopped the game and relaunched it with no sweeper behind it.
# `&` must sit inside `{ ... }`: at list level `&` binds EVERYTHING to its
# left into one background job, which would run force-stop concurrently with
# the relaunch. `pkill` gets `|| :` because an already-dead sweeper makes it
# exit 1 and that must not abort the chain.
line = (
    # 1. deploy the fixed script to a FRESH path (overwriting a file the old
    #    bash may still be reading can corrupt the running instance), then
    #    prove the decode produced a script carrying the dd fix
    "exec echo %s | base64 -d > %s/sweep_fixed.sh" % (b64, D)
    + " && grep -q '^#!/usr/bin/env bash' %s/sweep_fixed.sh" % D
    + " && grep -c 'su 0 sh -c' %s/sweep_fixed.sh" % D
    # 2. retire the old one: STOP file first (its loop checks that every
    #    ~0s cycle), pkill as the backstop
    + " && touch %s/sweep/STOP && sleep 6" % D
    + " && { pkill -f '%s/sweep.sh' || :; }" % D
    + " && sleep 2"
    + " && echo OLD-SWEEPER:$(pgrep -af 'sweep.sh' | grep -v fixed | tr '\\n' ' ')"
    # 3. STOP must be GONE before the new instance starts, or it dies on line 1
    + " && rm -f %s/sweep/STOP" % D
    # 4. kill the game with no sweeper watching (an instance that sees an
    #    empty pid quits instead of waiting)
    + " && %s shell am force-stop jp.konami.pesam && sleep 3" % S
    # 5+6 start the fixed sweeper, THEN relaunch, so cycle 1 covers the fresh
    #    login and sweeper + mitm observe the SAME session
    + " && { nohup bash %s/sweep_fixed.sh >> %s/sweep.log 2>&1 </dev/null &"
    " sleep 5 && { %s shell am start -W -a android.intent.action.MAIN"
    " -c android.intent.category.LAUNCHER"
    " -n jp.konami.pesam/com.epicgames.ue4.GameActivity || :; }; }" % (D, D, S)
    # proof -- printed, never assumed
    + " && sleep 8 && echo SEQUENCE-DONE"
    + " && echo NEW-SWEEPER:$(pgrep -af 'sweep_fixed' | tr '\\n' ' ')"
    + " && echo GAMEPID:$(%s shell pidof jp.konami.pesam | tr -d '\\r')" % S
    + " && echo SWEEP-DIR:$(du -sh %s/sweep | cut -f1)" % D
    + " && tail -6 %s/sweep.log" % D
)
assert "\n" not in line and "\r" not in line
open(OUT, "w", newline="\n").write(line)
print("cmd bytes:", len(line))
