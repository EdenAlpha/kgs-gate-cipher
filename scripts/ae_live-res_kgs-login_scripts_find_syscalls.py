#!/usr/bin/env python3
"""Why "Insufficient randomness"?  Check for RAW syscalls (svc #0).

If the game's curl calls getrandom()/openat()/read() via raw `svc #0`
instead of libc imports, the emulator silently ignores them (Unicorn does
not emulate syscalls), the entropy buffer stays zero, and curl aborts with
"Insufficient randomness" -- which is exactly the error we see.

Also lists every entropy-related import so we can see what it actually asks.
"""
from __future__ import annotations

import json
import sys

import numpy as np

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
TEXT_V = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

data = open(SO, "rb").read()

print("=== entropy-related imports (from plt_map.json) ===", flush=True)
plt = json.load(open(r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
                     r"\peerlink_work\apk_lab\analysis\plt_map.json"))
names = sorted({v["sym"] for v in plt.values()})
KEYS = ("random", "getr", "urandom", "entropy", "rand", "open", "read",
        "dlsym", "dlopen", "clock", "time", "syscall", "prctl", "getcpu")
for n in names:
    low = n.lower()
    if any(k in low for k in KEYS) and not low.startswith("_zn5physx"):
        print(f"   {n}", flush=True)

print("\n=== raw `svc #0` syscalls in .text ===", flush=True)
w = np.frombuffer(data, dtype="<u4", count=TEXT_SIZE // 4,
                  offset=TEXT_OFF)
pcs = TEXT_V + np.arange(len(w), dtype="<u8") * 4
svc = np.nonzero(w == np.uint32(0xD4000001))[0]
print(f"   total `svc #0` = {len(svc)}", flush=True)

# recover the syscall number from the preceding MOVZ/MOVK x8, #nr
NAME = {278: "getrandom", 56: "openat", 63: "read", 57: "close",
        62: "lseek", 64: "write", 78: "readlinkat", 17: "gettimeofday",
        113: "clock_gettime", 222: "mmap", 215: "munmap", 214: "brk",
        93: "exit", 94: "exit_group", 124: "sched_yield", 98: "futex",
        226: "mprotect", 233: "madvise", 220: "clone", 172: "getpid",
        167: "prctl", 165: "getrusage", 261: "prlimit64", 276: "renameat2",
        48: "faccessat", 79: "fstatat", 80: "fstat", 25: "fcntl",
        29: "ioctl", 35: "nanosleep", 115: "clock_getres", 131: "tgkill",
        178: "gettid", 198: "socket", 203: "bind", 200: "connect"}
counts = {}
samples = {}
for i in svc[:200000]:
    nr = None
    for k in range(1, 12):
        j = i - k
        if j < 0:
            break
        w2 = int(w[j])
        if (w2 & 0xFF80001F) == 0xD2800008:        # MOVZ x8, #imm
            nr = (w2 >> 5) & 0xFFFF
            break
        if (w2 & 0xFF80001F) == 0xF2800008:        # MOVK x8, #imm, lsl 16
            nr = ((w2 >> 5) & 0xFFFF) << 16
    key = NAME.get(nr, f"nr={nr}")
    counts[key] = counts.get(key, 0) + 1
    samples.setdefault(key, int(pcs[i]))

for k, v in sorted(counts.items(), key=lambda x: -x[1])[:30]:
    print(f"   {k:20s} x{v:<8d} e.g. {samples[k]:#x}", flush=True)
sys.exit(0)
