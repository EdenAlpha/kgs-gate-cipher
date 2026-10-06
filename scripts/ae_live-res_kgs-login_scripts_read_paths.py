#!/usr/bin/env python3
"""Read CommandRequest.path out of the running game WITHOUT injecting into it.

Frida is unusable against eFootball 11.0.1. Both injection paths are rejected
the same way:

    Spawning `jp.konami.pesam`...
    Failed to spawn: error receiving data: Connection reset by peer

    Attaching...
    Failed to attach: error receiving data: Connection reset by peer

The game kills itself either way, so nothing that injects will survive long
enough to read a single byte. But it does not need to know it is being read.

Linux offers `/proc/<pid>/mem`, which lets a reader with sufficient privilege
read another process's address space directly, with no code injected, no
thread created inside the target, and nothing written to the target's memory.
redroid runs as root, so the container's own `dd` can do it. From the game's
point of view this is indistinguishable from a debugger that is not there: no
`/proc/self/maps` entry, no extra thread, no modified code.

The route table is what this is for. `CommandRequest` is
`{id=1 string, packMode=2 enum, req=3 string, path=4 string}`, and the game
serialises it in its own heap before handing it to TLS, so `path` is on the
plank at some point during startup. Finding it needs no offset and no TLS
break, only a reader.

Two things make this reliable rather than lucky:

  * The message exists only for as long as it takes to hand it to the
    transport. So the scan repeats over the whole startup window instead of
    sweeping once. Boot was measured to reach the first gRPC traffic around
    t=43s, and the window is kept open well past that.
  * Every hit is fully decoded and must parse as one complete CommandRequest,
    in field order, before it is reported -- the same strictness the in-process
    scanner uses. A plausible-looking string is not a result.

Usage (inside the container, as root):
    python3 read_paths.py --package jp.konami.pesam --seconds 240
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

TAG_PATH = 0x22          # field 4, wire type 2 (length-delimited)
MAX_PATH = 96
EXPECTED_FIELDS = [1, 2, 3, 4]
MIN_REGION = 1 << 20     # skip tiny regions; routes are not in a 4 KB page
CHUNK = 1 << 22          # 4 MiB per dd read


# Command prefix used to reach the target. The reader runs on the HOST and the
# game runs inside redroid, so every access goes through `docker exec`. redroid
# ships no interpreter, which is why this cannot simply be run inside the
# container -- that produced:
#     OCI runtime exec failed: exec: "python3": executable file not found in $PATH
DOCKER_EXEC = ["sudo", "docker", "exec", "redroid"]


def sh(cmd, timeout=120):
    """Run a shell command in the target and return stdout as bytes."""
    r = subprocess.run(DOCKER_EXEC + ["sh", "-c", cmd],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       timeout=timeout)
    return r.stdout


def pidof(pkg):
    out = sh("pidof %s 2>/dev/null" % pkg).decode("utf-8", "replace")
    for tok in out.split():
        if tok.isdigit():
            return int(tok)
    return None


def maps_lines(pid):
    return sh("cat /proc/%d/maps 2>/dev/null" % pid).decode(
        "utf-8", "replace").splitlines()


def readable_regions(pid, want_heap=True):
    """Return [(start, end)] of readable, writable, non-executable regions.

    Filtered to rw- plus the anonymous/heap entries, which is where a freshly
    serialised message lands. Deliberately skips file-backed mappings: the game
    binary's own .rodata is 160 MB of mostly non-ASCII data that would cost
    more to scan than it could ever return.
    """
    out = []
    for ln in maps_lines(pid):
        m = re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\d+\s*(.*)$",
                     ln)
        if not m:
            continue
        start, end, perm = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
        name = (m.group(4) or "").strip()
        if "r" not in perm or "w" not in perm or "x" in perm:
            continue
        if end - start < MIN_REGION:
            continue
        if name and not name.startswith("["):
            continue          # file-backed: skip
        if not name and want_heap:
            pass               # anonymous mappings are the interesting ones
        out.append((start, end))
    return out


def uvarint(buf, i):
    v, shift = 0, 0
    for _ in range(10):
        if i >= len(buf):
            return None
        b = buf[i]
        v |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            return v, i
        shift += 7
    return None


def latin(b):
    for c in b:
        if c < 0x20 or c > 0x7E:
            return None
    return b.decode("latin1")


def decode_command_request(buf, start, length):
    """Strictly decode one CommandRequest. Returns dict or None.

    Requires the exact field run id=1, packMode=2, req=3, path=4, once each and
    in order, and nothing else. A permissive decoder is the trap here: the
    scanner finds candidates by spotting a 0x22 byte, so it will happily decode
    a valid *suffix* of some unrelated message as if it were a whole request.
    """
    out = {"id": None, "packMode": None, "req": None, "path": None}
    i, seen = start, 0
    end = start + length
    while i < end:
        k = uvarint(buf, i)
        if not k:
            return None
        key, i = k
        fn, wt = key >> 3, key & 7
        if seen >= len(EXPECTED_FIELDS) or fn != EXPECTED_FIELDS[seen]:
            return None
        if fn == 2:
            if wt != 0:
                return None                      # packMode is an enum
        elif wt != 2:
            return None                          # the rest are strings
        seen += 1
        if wt == 2:
            l = uvarint(buf, i)
            if not l:
                return None
            ln, i = l
            if i + ln > end:
                return None
            s = latin(buf[i:i + ln])
            if s is None:
                return None
            if fn == 1:
                out["id"] = s
            elif fn == 3:
                out["req"] = s
            else:
                out["path"] = s
            i += ln
        else:
            v = uvarint(buf, i)
            if not v:
                return None
            if fn == 2:
                out["packMode"] = v[0]
            i = v[1]
    if seen != len(EXPECTED_FIELDS):
        return None
    return out


def read_region(pid, start, end):
    """Pull a region out of the target with dd over /proc/pid/mem."""
    n = end - start
    parts = []
    off = start
    left = n
    while left > 0:
        want = min(CHUNK, left)
        # bs=1 with a byte skip is exact but slow in coreutils; bs=4096 with a
        # page skip is exact here because every region start is page aligned
        if off % 4096 == 0:
            cmd = ("dd if=/proc/%d/mem bs=4096 skip=%d count=%d "
                   "status=none 2>/dev/null"
                   % (pid, off // 4096, want // 4096))
        else:
            cmd = ("dd if=/proc/%d/mem bs=1 skip=%d count=%d "
                   "status=none 2>/dev/null" % (pid, off, want))
        try:
            got = sh(cmd, timeout=180)
        except subprocess.TimeoutExpired:
            break
        if not got:
            break
        parts.append(got)
        off += len(got)
        left -= len(got)
        if len(got) < want:
            break
    return b"".join(parts), n


def scan_buffer(buf, found):
    """Find CommandRequests in a buffer.

    Candidate location is done with bytes.find, which runs at C speed, and only
    the handful of bytes around each 0x22 are handed to the strict decoder.

    This matters enormously and was the reason a whole run found nothing: a
    per-byte Python loop over 2 GB took 152 s per pass, so only two passes fit
    in the 300 s window. A request that lives for about a millisecond has
    roughly a 0.001% chance of being sampled that way. The message was not
    absent -- it was never looked at. Locating candidates with find() drops a
    pass to a couple of seconds, which makes continuous coverage possible.
    """
    hits = 0
    if not buf:
        return hits
    needle = bytes([TAG_PATH])
    # Prefilters, cheapest first. Both only discard work; the strict decoder
    # still decides every survivor, so correctness never depends on them.
    #
    #   1. the length byte must be 1..96
    #   2. the byte after it must be printable ASCII
    #
    # Measured on 8 MB of random bytes: 32765 x 0x22, 12154 pass (1), 4564 pass
    # (2). Heap data is mostly zeroes and pointers with long printable runs, so
    # (2) removes far less than the raw-byte arithmetic suggests -- which is why
    # the sampling rate, not the filter, is what makes this practical.
    printable = bytes(range(0x20, 0x7F))
    pos = 0
    while True:
        i = buf.find(needle, pos)
        if i < 0 or i + 3 > len(buf):
            break
        pos = i + 1
        plen = buf[i + 1]
        if plen < 1 or plen > MAX_PATH:
            continue
        if buf[i + 2:i + 3] not in printable:
            continue
        lo = max(0, i - 96)
        seg = buf[lo:i + 2 + plen]
        for back in range(min(96, i), 1, -1):
            off = i - lo - back
            if off < 0:
                break
            cr = decode_command_request(seg, off, back + 2 + plen)
            if cr and cr["path"]:
                key = cr["path"]
                if key not in found:
                    found[key] = {"packMode": cr["packMode"], "req": cr["req"],
                                  "id": cr["id"], "seen": 1}
                    hits += 1
                    print("[scan] path=%s  packMode=%s  id=%s  req=%s"
                          % (json.dumps(key), cr["packMode"],
                             json.dumps(cr["id"]), json.dumps(cr["req"])),
                          flush=True)
                else:
                    found[key]["seen"] += 1
                break
    return hits


class DirtySet:
    """Track which pages changed since the last pass.

    The problem this solves is sampling, not parsing. A serialised
    CommandRequest lives for roughly a millisecond, so re-reading 2 GB in 152 s
    and doing it twice in the whole window cannot catch one. But a page of a
    live process changes only where it is actually being written, and the gRPC
    stack's serialisation buffer is a small, busy region. Comparing against the
    previous snapshot means the hot regions are re-scanned every pass at a small
    cost, while the 2 GB of quiet heap is read once and then skipped.

    Pages are keyed by region so a shrinking or growing region does not compare
    against the wrong bytes.
    """

    def __init__(self, page=4096):
        self.page = page
        self.prev = {}          # (start, end) -> {page_index: bytes}

    def changed(self, start, end, buf):
        """Yield only the byte ranges of `buf` that differ from last pass."""
        key = (start, end)
        old = self.prev.get(key)
        n = self.page
        cur = {}
        out = []
        if old is None or len(old) != (len(buf) + n - 1) // n:
            out.append((0, len(buf)))
        else:
            for pi in range((len(buf) + n - 1) // n):
                page = buf[pi * n:(pi + 1) * n]
                cur[pi] = page
                if old.get(pi) != page:
                    lo = pi * n
                    # widen by a page on each side: a message can straddle a
                    # boundary and the decoder needs the preceding fields
                    lo2 = max(0, lo - 128)
                    hi2 = min(len(buf), lo + n + 128)
                    out.append((lo2, hi2))
            self.prev[key] = cur
            return out
        for pi in range((len(buf) + n - 1) // n):
            cur[pi] = buf[pi * n:(pi + 1) * n]
        self.prev[key] = cur
        return out

    def forget(self, key):
        self.prev.pop(key, None)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", default="jp.konami.pesam")
    ap.add_argument("--seconds", type=int, default=240)
    ap.add_argument("--interval", type=float, default=0.2)
    ap.add_argument("--huge-mb", type=int, default=96,
                    help="regions larger than this are read only once, early; "
                         "the 537 MB reservations are mostly untouched and cost "
                         "150 s each to walk")
    ap.add_argument("--docker-exec", default=None,
                    help="command prefix to reach the container, e.g. "
                         "'sudo docker exec redroid'. Omit to run directly "
                         "against the local pid namespace.")
    a = ap.parse_args()

    global DOCKER_EXEC
    if a.docker_exec:
        DOCKER_EXEC = a.docker_exec.split()
    print("[scan] reaching the target via: %s" % " ".join(DOCKER_EXEC),
          flush=True)

    pid = pidof(a.package)
    if pid is None:
        print("[scan] %s is not running" % a.package)
        return 2
    print("[scan] pid=%d, reading /proc/%d/mem for %ds (no injection)"
          % (pid, pid, a.seconds), flush=True)
    regs = readable_regions(pid)
    hot_limit = a.huge_mb * 1000 * 1000
    hot = [(s, e) for s, e in regs if (e - s) <= hot_limit]
    cold = [(s, e) for s, e in regs if (e - s) > hot_limit]
    print("[scan] %d region(s): %d frequent (%.1f MB) + %d large (%.1f MB)"
          % (len(regs), len(hot), sum(e - s for s, e in hot) / 1e6,
             len(cold), sum(e - s for s, e in cold) / 1e6), flush=True)
    for s, e in (hot[:8] + cold[:4]):
        print("        %#018x-%#018x  %.1f MB%s"
              % (s, e, (e - s) / 1e6, "  (large)" if (e - s) > hot_limit else ""),
              flush=True)
    if not regs:
        print("[scan] no usable regions; check the maps output above")
        return 2

    found = {}
    deadline = time.time() + a.seconds

    # The large reservations are walked once, up front. A freshly serialised
    # message is a small malloc chunk in a busy region; spending 150 s per pass
    # to cover two untouched 537 MB reservations would leave two samples of the
    # whole process in the entire window, which cannot catch something that
    # lives for a millisecond.
    if cold:
        t0 = time.time()
        got = 0
        for s, e in cold:
            buf, _ = read_region(pid, s, e)
            got += len(buf)
            if buf:
                scan_buffer(buf, found)
        print("[scan] large regions: %.1f MB in %.1fs, %d path(s)"
              % (got / 1e6, time.time() - t0, len(found)), flush=True)
        if found:
            print(json.dumps(found, indent=2, sort_keys=True))
            return 0

    passes = 0
    last_maps = 0.0
    dirty = DirtySet()
    scan_mb = 0.0
    t_start = time.time()
    while time.time() < deadline:
        passes += 1
        t0 = time.time()
        got = 0
        scanned = 0
        # re-read the maps periodically: new regions appear as the game allocates
        if time.time() - last_maps > 5.0:
            last_maps = time.time()
            fresh = readable_regions(pid)
            known = set(hot) | set(cold)
            added = [(s, e) for s, e in fresh
                     if (e - s) <= hot_limit and (s, e) not in known]
            if added:
                hot += added
                print("[scan] +%d new region(s), now %d frequent"
                      % (len(added), len(hot)), flush=True)
        for s, e in hot:
            buf, _ = read_region(pid, s, e)
            got += len(buf)
            if not buf:
                continue
            for lo, hi in dirty.changed(s, e, buf):
                chunk = buf[lo:hi]
                scanned += len(chunk)
                scan_buffer(chunk, found)
            if found:
                break
        scan_mb += scanned / 1e6
        alive = pidof(a.package)
        dt = max(1e-6, time.time() - t0)
        print("[scan] pass %d: read %.1f MB, rescanned %.2f MB in %.2fs "
              "(%d passes, %.1f MB rescanned total), %d path(s)%s"
              % (passes, got / 1e6, scanned / 1e6, dt, passes, scan_mb,
                 len(found), "" if alive else "  [game exited]"), flush=True)
        if found:
            print("[scan] paths: %s" % json.dumps(sorted(found)), flush=True)
            print(json.dumps(found, indent=2, sort_keys=True))
            return 0
        if alive is None:
            print("[scan] game exited before any CommandRequest was seen")
            print("PASSES=%d PATHS=0" % passes)
            return 1
        time.sleep(a.interval)

    print("[scan] %d pass(es) over %ds, no CommandRequest found"
          % (passes, a.seconds))
    print("PASSES=%d PATHS=%d" % (passes, len(found)))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
