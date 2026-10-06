#!/usr/bin/env bash
# Arm the TLS interceptor, now that Play has finished downloading.
#
# Ordering is not cosmetic here. Play will not download its asset packs through a
# proxy whose certificate it rejects, so interception and the download could not
# overlap: arming this before the packs land produces a bare "Download Failed 0%"
# on the game's splash with nothing pointing at the recorder as the cause. That
# cost hours. It is safe now only because the install is finished.
#
# The step that actually makes interception work on Android 14 is the Conscrypt
# bind-mount. The CA installs correctly by subject hash into
# /system/etc/security/cacerts, and every app still refuses the proxy's
# certificate, because Conscrypt reads its own copy of the trust store from
# /apex/com.android.conscrypt/cacerts -- 134 certificates, none of them ours.
# After the bind mount that directory reports 135 and ours is in it.
#
# Usage:  bash arm_recorder.sh [container] [workdir]
set -uo pipefail

C="${1:-redroid}"
W="${2:-/tmp/kgs}"
mkdir -p "$W"
say() { echo "rec: $*"; }

# The repo copy may not be on the runner's checkout; fetch it if missing.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "$SCRIPT_DIR/setup_ca.sh" ]; then
  say "fetching setup_ca.sh"
  curl -fsSL --max-time 60 \
    https://raw.githubusercontent.com/EdenAlpha/peerlink-efootball-disconnects/main/kgs-login/scripts/setup_ca.sh \
    -o "$SCRIPT_DIR/setup_ca.sh" || say "could not fetch setup_ca.sh"
fi

say "installing the CA"
bash "$SCRIPT_DIR/setup_ca.sh" "$C" "$W/ca" 2>&1 | tail -5
HASH=$(cat "$W/ca/ca.hash" 2>/dev/null)
say "ca hash: ${HASH:-<none>}"

say "binding the system trust store over the Conscrypt apex"
adb -s 127.0.0.1:5555 shell su 0 mount --bind \
  /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts 2>&1 | tail -2
say "  system store: $(adb -s 127.0.0.1:5555 shell su 0 ls /system/etc/security/cacerts 2>/dev/null | wc -l) certs"
say "  apex store:   $(adb -s 127.0.0.1:5555 shell su 0 ls /apex/com.android.conscrypt/cacerts 2>/dev/null | wc -l) certs"
if [ -n "$HASH" ]; then
  adb -s 127.0.0.1:5555 shell su 0 ls -l \
    "/apex/com.android.conscrypt/cacerts/$HASH.0" 2>&1
fi

say "restarting zygote so the trust store is re-read"
sudo docker exec "$C" sh -c 'setprop ctl.restart zygote' 2>/dev/null || true
sleep 25
adb connect 127.0.0.1:5555 2>&1 | tail -1
for i in $(seq 1 60); do
  [ "$(adb -s 127.0.0.1:5555 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] \
    && { say "  phone back after $((i*5))s"; break; }
  sleep 5
done

say "starting mitmproxy, signing with OUR ca"
python3 -m pip install --quiet --break-system-packages mitmproxy 2>&1 | tail -1
mkdir -p "$W/mitm"
if [ -f "$W/ca/ca.key" ]; then
  cat "$W/ca/ca.key" "$W/ca/ca.crt" > "$W/mitm/mitmproxy-ca.pem"
  cp -f "$W/ca/ca.crt" "$W/mitm/mitmproxy-ca-cert.pem"
else
  say "  no ca.key; mitmproxy will use its own CA, which the phone does not trust"
fi
if [ ! -f "$SCRIPT_DIR/mitm_addon.py" ]; then
  curl -fsSL --max-time 60 \
    https://raw.githubusercontent.com/EdenAlpha/peerlink-efootball-disconnects/main/kgs-login/scripts/mitm_addon.py \
    -o "$SCRIPT_DIR/mitm_addon.py" || say "could not fetch the addon"
fi
FLOWS_LOG=$W/flows.log nohup setsid mitmdump \
  --mode transparent --listen-port 8080 \
  --set confdir="$W/mitm" -s "$SCRIPT_DIR/mitm_addon.py" \
  -w "$W/flows.mitm" > "$W/mitm.log" 2>&1 < /dev/null &
sleep 14
grep -q ADDON-READY "$W/flows.log" 2>/dev/null \
  && say "  proxy up, addon loaded" \
  || { say "  === PROXY OR ADDON DID NOT START ==="; head -20 "$W/mitm.log"; }

say "arming DNAT on the docker bridge"
sudo modprobe iptable_nat 2>/dev/null || true
HOSTGW=$(ip -4 addr show docker0 2>/dev/null | grep -oE "inet [0-9.]+" | head -1 | cut -d" " -f2)
say "  docker0 gateway: [$HOSTGW]"
sudo iptables-legacy -t nat -A PREROUTING -i docker0 -p tcp \
  --dport 443 -j DNAT --to-destination "$HOSTGW:8080" 2>&1
sudo iptables-legacy -t nat -L PREROUTING -n | head -4

say "packet capture for the whole session"
sudo docker exec "$C" sh -c \
  'rm -f /data/local/tmp/game2.pcap; nohup tcpdump -i any -s 0 -w /data/local/tmp/game2.pcap tcp >/data/local/tmp/tcpdump2.out 2>&1 &' 2>/dev/null

say "RECORDER ARMED"
exit 0
