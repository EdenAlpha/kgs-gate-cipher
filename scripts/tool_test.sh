#!/usr/bin/env bash
# Step 2 of the plan: three yes/no questions about the DEVICE, right now,
# no game needed. One YES/NO line per door, with the evidence beside it.
# Silence is never an answer here: empty values print as <empty>, and every
# number printed is a real byte count, never an assumed one.
#
# All three doors are tested against a sleep WE start, so no app -- Play
# mid-download included -- can be left stopped by a test.
set -u
S=127.0.0.1:5555
say() { echo "T: $*"; }
say "step2 door test at $(date -u +%H:%M:%S)"

say "--- root"
ROOT=$(adb -s "$S" shell su 0 id -u 2>/dev/null | tr -d '\r' | head -1)
say "root=[${ROOT:-<empty>}]"
[ "$ROOT" = "0" ] || { say "RESULT root=FAILED eBPF=? ptrace=? sigstop_memread=?"; exit 1; }

BOOT=$(adb -s "$S" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
say "boot_completed=[${BOOT:-<empty>}]"
[ "$BOOT" = "1" ] || { say "DEVICE NOT ANSWERING - stopping"; exit 1; }

# door 1 -- eBPF: does the kernel expose what a bpf program needs?
say "--- door 1: eBPF"
BTF=$(adb -s "$S" shell su 0 ls /sys/kernel/btf/vmlinux 2>/dev/null | tr -d '\r')
DIS=$(adb -s "$S" shell su 0 cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null | tr -d '\r')
case "$BTF" in
  /sys/kernel/btf/vmlinux) EBPF="YES" ;;
  *) EBPF="NO" ;;
esac
say "eBPF: $EBPF  (btf=[${BTF:-<empty>}] unprivileged_bpf_disabled=[${DIS:-<empty>}])"

# door 2 -- ptrace: can a tracer attach to a live process on this device?
say "--- door 2: ptrace"
STRACE=$(adb -s "$S" shell su 0 which strace 2>/dev/null | tr -d '\r')
TPID=$(adb -s "$S" shell su 0 sh -c 'sleep 60 & echo $!' 2>/dev/null | tr -d '\r' | head -1)
say "strace=[${STRACE:-<empty>}] our sleep pid=[${TPID:-<empty>}]"
PTRACE="UNTESTED"
if [ -n "${STRACE:-}" ] && [ -n "${TPID:-}" ]; then
  OUT=$(timeout 6 adb -s "$S" shell su 0 strace -p "$TPID" -e trace=none 2>&1 | tr -d '\r' | head -3)
  case "$OUT" in
    *ttached*) PTRACE="YES" ;;
    *) PTRACE="NO" ;;
  esac
  say "ptrace: $PTRACE  (attach said: [$(printf '%s' "$OUT" | tr '\n' ' ' | head -c 200)])"
  adb -s "$S" shell su 0 pkill strace >/dev/null 2>&1
else
  say "ptrace: UNTESTED  (strace is not installed on the device)"
fi
# our sleep must not be left behind, traced or not
adb -s "$S" shell su 0 kill -9 "$TPID" >/dev/null 2>&1

# door 3 -- SIGSTOP + read /proc/<pid>/mem: the sweeper's own mechanism.
say "--- door 3: SIGSTOP + /proc/pid/mem"
MPID=$(adb -s "$S" shell su 0 sh -c 'sleep 60 & echo $!' 2>/dev/null | tr -d '\r' | head -1)
say "our sleep pid=[${MPID:-<empty>}]"
SIG="NO"
if [ -n "${MPID:-}" ]; then
  adb -s "$S" shell su 0 kill -STOP "$MPID" >/dev/null 2>&1
  sleep 1
  STATE=$(adb -s "$S" shell su 0 cat /proc/"$MPID"/status 2>/dev/null | tr -d '\r' | grep '^State' | head -1)
  RSTART=$(adb -s "$S" shell su 0 cat /proc/"$MPID"/maps 2>/dev/null | tr -d '\r' \
           | awk '$2 ~ /^r/ {split($1,a,"-"); print a[1]; exit}')
  NB=$(adb -s "$S" exec-out "su 0 sh -c 'dd if=/proc/$MPID/mem bs=4096 skip=$(( 0x${RSTART:-0} / 4096 )) count=8 2>/dev/null'" 2>/dev/null | wc -c | tr -d ' \r')
  adb -s "$S" shell su 0 kill -9 "$MPID" >/dev/null 2>&1
  # 8 pages requested; only a full 32768 bytes counts as a read. dd prints
  # statistics to stderr, and if even those leaked into stdout they would be
  # a few dozen bytes -- they can never masquerade as 32768.
  if [ "${NB:-0}" -ge 32768 ]; then SIG="YES"; fi
  say "SIGSTOP+read: $SIG  ([${STATE:-<empty>}] read=${NB:-0}B of 32768 from 0x${RSTART:-?})"
else
  say "SIGSTOP+read: NO  (could not start a sleep on the device)"
fi

say "RESULT root=$ROOT eBPF=$EBPF ptrace=$PTRACE sigstop_memread=$SIG"
exit 0
