#!/usr/bin/env python3
"""Dump raw rodata context around config-key strings; look for JSON/defaults.
   Also dump functions that reference the key table."""
import struct, os, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
OUT = os.path.join(HERE, "key_context.txt")

KEYS = [
    "TurnReconnectWaitTimeMs", "NtlReconnectWaitTimeMs", "NameResolverTimeoutMs",
    "NetworkIoConnectionTimeoutUs", "MaxPayloadLength", "BindNTLAddress",
    "ChangeoverPeerReceiveIdleTimeMsThreshold", "KeepAliveTimerUs",
    "MatchAbortTimerCoefficient", "NTL_PEER_KEEPALIVE_COUNT",
    "MultiplaySessionRecvThreadReceiveTimeoutUs", "CHECK_STUN_RTT_TIMEOUT",
    "is_cheat_user", "reflexive_address", "OnlineModeTaskCheckCheat",
    "DETECT_NAT_ABORTED", "CmdGetTurnServerList",
]


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
    out = []
    for k in KEYS:
        b = k.encode()
        s = 0
        hits = 0
        while hits < 3:
            i = data.find(b, s)
            if i < 0:
                break
            s = i + 1
            hits += 1
            va = off2va(ph, i)
            # context: 160 bytes before/after as ascii
            lo = max(0, i - 200)
            hi = min(len(data), i + len(b) + 400)
            raw = data[lo:hi]
            txt = "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
            out.append("\n=== %s  @ file 0x%x  va 0x%s ===" % (
                k, i, format(va, "x") if va else "?"))
            out.append("ASCII: " + txt)
            # also hexdump the tail after the key (possible default nearby)
            tail = data[i + len(b): i + len(b) + 64]
            out.append("TAIL: " + " ".join("%02x" % c for c in tail))
    open(OUT, "w", encoding="utf-8", errors="replace").write("\n".join(out))
    print("WROTE %s lines=%d" % (OUT, len(out)))


if __name__ == "__main__":
    main()
