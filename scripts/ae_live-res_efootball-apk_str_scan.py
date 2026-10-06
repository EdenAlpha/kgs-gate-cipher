#!/usr/bin/env python3
"""Extract all ASCII strings matching stop/abort/giveup/timeout/idle rules
   from libUE4.so rodata. Output: rule_strings.txt"""
import struct, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
OUT = os.path.join(HERE, "rule_strings.txt")

PAT = re.compile(
    rb"(MATCH_STOP|STOP_MATCH|MATCH_ABORT|MatchAbort|ABORT_|_ABORTED|GIVE_UP|"
    rb"BUF_EMPTY|RECEIVE_IDLE|ReceiveIdle|IdleTime|IDLE_TIME|"
    rb"Watchdog|WATCHDOG|WatchDog|LinkTimeout|LINK_TIMEOUT|"
    rb"RecvTimeout|RECV_TIMEOUT|RECEIVE_TIMEOUT|RECV_THREAD|"
    rb"Disconnect|DISCONNECT|TimeoutMs|TimeoutUs|TimeoutSec|"
    rb"giveup|GiveUp|give_up|heartbeat|Heartbeat|HEARTBEAT|"
    rb"ConnectionTimeout|CONN_TIMEOUT|Stall|STALL|stall)", re.I)


def parse_elf(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    ph = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, o)
        p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", data, o + 8)
        if p_type == 1:
            ph.append((p_offset, p_vaddr, p_filesz, p_flags))
    return ph


def off2va(ph, off):
    for po, pv, pf, _ in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


def main():
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    found = {}
    for m in PAT.finditer(data):
        # expand to full C-string bounds
        s = m.start()
        while s > 0 and data[s - 1] != 0 and 0x20 <= data[s - 1] <= 0x7e:
            s -= 1
        e = m.end()
        while e < len(data) and data[e] != 0 and 0x20 <= data[e] <= 0x7e:
            e += 1
        b = data[s:e]
        if not (6 <= len(b) <= 140):
            continue
        try:
            t = b.decode("ascii")
        except Exception:
            continue
        if not re.fullmatch(r"[\x20-\x7e]+", t):
            continue
        va = off2va(ph, s)
        found[t] = va

    lines = []
    lines.append("unique rule-ish strings: %d" % len(found))
    for t in sorted(found, key=lambda x: x.lower()):
        lines.append("  0x%s  %s" % (format(found[t], "x") if found[t] else "?", t))
    open(OUT, "w", encoding="utf-8", errors="replace").write("\n".join(lines))
    print("WROTE %s lines=%d" % (OUT, len(lines)))


if __name__ == "__main__":
    main()
