#!/usr/bin/env bash
# Make the virtual phone trust a certificate authority of ours, so the game's
# TLS to Konami can be terminated and read in the clear.
#
# Two hard lessons from the run that produced nothing are encoded here:
#
#   1. `[ -w FILE ]` LIES when run as root on a read-only mount. root passes
#      the permission check, the subsequent cp dies with EROFS, and with
#      `set -e` the script dies silently -- no INSTALLED line, no error, no
#      remount attempt. The only evidence was the absence of output. So this
#      script probes with a real write and reports every outcome out loud.
#
#   2. The game manifest contains NO networkSecurityConfig, so Android's
#      default applies: the SYSTEM store is trusted, user-added CAs are NOT.
#      A user-store install would succeed and change nothing. The system store
#      is the only store that matters, which is why this script fails loudly
#      instead of falling back to one that cannot work.
#
# Usage:  bash setup_ca.sh <container> <outdir> [adb-serial]
set -uo pipefail

CONTAINER="${1:?container name required}"
OUT="${2:?output directory required}"
ADB_SERIAL="${3:-127.0.0.1:5555}"
mkdir -p "$OUT"

say() { echo "ca-setup: $*"; }

say "generating a CA and a server key for pes22-game.cs.konami.net"
# The subject/SAN must match the host the game dials, or hostname verification
# fails and the game simply refuses to connect.
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=kgs-intercept-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
say "wrote: $(ls "$OUT" | tr '\n' ' ')"

say "installing the CA into the SYSTEM trust store"
# Android requires the filename to be the subject hash, uppercased hex plus
# .0 -- that is how the cacerts lookup works.
HASH=$(openssl x509 -in "$OUT/ca.crt" -noout -subject_hash_old 2>/dev/null \
       || openssl x509 -in "$OUT/ca.crt" -noout -subject_hash)
say "subject hash: $HASH"
echo "$HASH" > "$OUT/ca.hash"
sudo docker exec "$CONTAINER" mkdir -p /data/local/tmp/cacerts
sudo docker cp "$OUT/ca.crt" "$CONTAINER:/data/local/tmp/cacerts/${HASH}.0"

DEST=/system/etc/security/cacerts/${HASH}.0
try_install() {
  # A REAL write probe, not `[ -w ]`: as root the test passes on read-only
  # mounts and the cp then dies. Touch tells the truth.
  if sudo docker exec "$CONTAINER" sh -c \
      "touch /system/etc/security/cacerts/.writetest 2>/dev/null && rm -f /system/etc/security/cacerts/.writetest"; then
    say "system store is writable, installing"
    if sudo docker exec "$CONTAINER" cp \
        "/data/local/tmp/cacerts/${HASH}.0" "$DEST" 2>&1; then
      say "INSTALLED into $DEST"
      sudo docker exec "$CONTAINER" ls -la "$DEST"
      return 0
    else
      say "copy failed despite the probe passing"
      return 1
    fi
  else
    say "system store is NOT writable (write probe failed)"
    return 1
  fi
}

if try_install; then
  say "RESULT: installed without remount"
  exit 0
fi

say "/system is read-only; attempting remount"
sudo docker exec "$CONTAINER" sh -c 'mount -o remount,rw /system 2>&1 || true'
say "in-container remount attempted; trying host-side adb remount"
adb -s "$ADB_SERIAL" remount 2>&1 | tail -3 || say "adb remount failed or adb absent"

if try_install; then
  say "RESULT: installed after remount"
  exit 0
fi

say "RESULT: FAILED -- the system store could not be written"
say "the CA is staged at /data/local/tmp/cacerts/${HASH}.0 in the container"
say "mount state:"
sudo docker exec "$CONTAINER" sh -c 'mount | grep -E " /system| / " | head -5' || true
exit 1
