#!/usr/bin/env python3
"""
Capstone xref+context scanner for libUE4.so kill-rule strings.
No Ghidra, no analysis project, no 90-minute wait.
Pass 1: locate target strings -> VAs (ELF phdr mapping)
Pass 2: fast word scan for ADRP/ADD address materialisation in .text (numpy)
Pass 3: capstone disassembly of small windows around each xref -> thresholds/keys
Fallback: literal 8-byte pointer table -> owning code
Output: capstone_xrefs.txt
"""
import struct, sys, os, re

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "native", "lib", "arm64-v8a", "libUE4.so")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capstone_xrefs.txt")

TARGETS = [
    "E_TURN_ALLOCATION_MISSMATCH",
    "MATCH_STOP_COUNT_SELF_BUF_EMPTY",
    "TurnReconnectWaitTimeMs",
    "NTL_PEER_KEEPALIVE_COUNT",
    "KeepAliveTimerUs",
    "reflexive_address",
    "CmdGetTurnServerList",
    "DETECT_NAT_ABORTED",
    "MatchAbortTimerCoefficient",
    "is_cheat_user",
    "OnlineModeTaskCheckCheat",
    "CHECK_STUN_RTT_TIMEOUT",
    "NTL_PEER_KEEPALIVE",
    "MultiplaySessionRecvThreadReceiveTimeoutUs",
    "GetIpAddressList",
    "CMD_GET_TURN_SERVER_LIST",
]

# known from earlier dataflow scan
KNOWN = ["0x7d2a9c0", "0x7d2aa38", "0x7c05b7c", "0x7d15db0", "0x7d4c400"]

try:
    import numpy as np
    HAVE_NP = True
except Exception:
    HAVE_NP = False

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.detail = True

lines = []
def log(s=""):
    lines.append(s)


def parse_elf(data):
    assert data[:4] == b"\x7fELF", "not ELF"
    ei_class = data[4]
    assert ei_class == 2, "expect 64-bit ELF"
    e_phoff, e_shoff = struct.unpack_from("<QQ", data, 32)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<QQQQQQ", data, off + 8)
        if p_type == 1:  # PT_LOAD
            phdrs.append((p_offset, p_vaddr, p_filesz, p_flags))
    return phdrs


def off2va(phdrs, off):
    for p_offset, p_vaddr, p_filesz, p_flags in phdrs:
        if p_offset <= off < p_offset + p_filesz:
            return p_vaddr + (off - p_offset), p_flags
    return None, None


def va2off(phdrs, va):
    for p_offset, p_vaddr, p_filesz, p_flags in phdrs:
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


def signext(val, bits):
    if val & (1 << (bits - 1)):
        val -= 1 << bits
    return val


def decode_adrp(insn, pc):
    # ADRP: op=1 immlo(2) 10000 immhi(19) Rd
    if (insn >> 24) & 0x9F != 0x90:
        return None
    rd = insn & 0x1F
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    imm = signext((immhi << 2) | immlo, 21)
    return rd, (pc & ~0xFFF) + (imm << 12)


def decode_add_imm(insn, rd):
    # ADD Xd,Xn,#imm12 (shift 0), 64-bit: 1001 0001 00 ...
    if (insn & 0xFF800000) != 0x91000000:
        return None
    if ((insn >> 22) & 0x3) != 0:
        return None
    rn = (insn >> 5) & 0x1F
    imm = (insn >> 10) & 0xFFF
    if (insn & 0x1F) != rd or rn != rd:
        return None
    return imm


def main():
    if not os.path.exists(LIB):
        log("LIB NOT FOUND: " + LIB)
        open(OUT, "w").write("\n".join(lines))
        return
    data = open(LIB, "rb").read()
    phdrs = parse_elf(data)
    log("LIB %s  size=%d  PT_LOAD=%d  numpy=%s" % (LIB, len(data), len(phdrs), HAVE_NP))

    # ---------- pass 1: strings -> VAs ----------
    strva = {}
    for t in TARGETS:
        b = t.encode()
        hits = []
        start = 0
        while True:
            i = data.find(b, start)
            if i < 0:
                break
            va, fl = off2va(phdrs, i)
            if va is not None:
                hits.append((i, va))
            start = i + 1
            if len(hits) >= 8:
                break
        strva[t] = hits
        log("\nSTRING %-46s hits=%d %s" % (t, len(hits),
            " ".join("0x%x" % h[1] for h in hits[:4])))

    # ---------- pass 2: find executable ranges ----------
    exec_ranges = []
    for p_offset, p_vaddr, p_filesz, p_flags in phdrs:
        if p_flags & 1:  # PF_X
            exec_ranges.append((p_vaddr, p_filesz, p_offset))
    log("\nexec ranges: " + ", ".join("0x%x+0x%x" % (v, s) for v, s, _ in exec_ranges))

    wanted = set()
    for hits in strva.values():
        for _, va in hits:
            wanted.add(va)
    for k in KNOWN:
        try:
            wanted.add(int(k, 16))
        except Exception:
            pass

    xref_hits = []   # (pc_of_addr, materialized_addr)

    for vaddr, filesz, p_offset in exec_ranges:
        # read as 4-byte words
        chunk = data[p_offset:p_offset + filesz]
        n = len(chunk) // 4
        if HAVE_NP:
            arr = np.frombuffer(chunk[:n * 4], dtype=np.uint32)
            adrp_idx = np.nonzero((arr >> 24) & np.uint32(0x9F) == np.uint32(0x90))[0]
        else:
            adrp_idx = [i for i in range(n)
                        if ((chunk[i * 4:i * 4 + 4] and
                             struct.unpack_from("<I", chunk, i * 4)[0] >> 24) & 0x9F) == 0x90]
        log("ADRP candidates in 0x%x: %d" % (vaddr, len(adrp_idx)))
        for i in adrp_idx:
            if HAVE_NP:
                i = int(i)
            pc = vaddr + i * 4
            insn = struct.unpack_from("<I", chunk, i * 4)[0]
            dec = decode_adrp(insn, pc)
            if dec is None:
                continue
            rd, page = dec
            # look ahead 16 instructions for ADD
            for j in range(1, 17):
                o = (i + j) * 4
                if o + 4 > len(chunk):
                    break
                nxt = struct.unpack_from("<I", chunk, o)[0]
                imm = decode_add_imm(nxt, rd)
                if imm is not None:
                    addr = page + imm
                    if addr in wanted:
                        xref_hits.append((pc, addr))
                    break
    log("\n=== ADRP/ADD xrefs found: %d ===" % len(xref_hits))

    # fallback: literal pointer table
    ptr_hits = []
    if len(xref_hits) < len(wanted):
        for va in sorted(wanted):
            needle = struct.pack("<Q", va)
            s = 0
            while True:
                i = data.find(needle, s)
                if i < 0:
                    break
                pva, fl = off2va(phdrs, i)
                if pva is not None:
                    ptr_hits.append((pva, va, fl))
                s = i + 1
                if len(ptr_hits) > 4000:
                    break
        log("literal pointer hits: %d" % len(ptr_hits))

    # ---------- pass 3: disassemble context ----------
    def disasm(va, before=0x60, after=0x120, tag=""):
        off = va2off(phdrs, va)
        if off is None:
            log("  (va 0x%x not in file)" % va)
            return
        start = max(0, off - before)
        buf = data[start:start + before + after]
        log("\n---- %s ctx @ 0x%x ----" % (tag, va))
        seen = 0
        for insn in MD.disasm(buf, va - before):
            mark = "<<<" if insn.address == va else ""
            op = insn.op_str
            note = ""
            if insn.mnemonic in ("mov", "movz", "movk") and "#" in op:
                m = re.search(r"#(0x[0-9a-fA-F]+|\d+)", op)
                if m:
                    try:
                        val = int(m.group(1), 0)
                        if val > 60:
                            note = "  ; imm=%d (0x%x)" % (val, val)
                    except Exception:
                        pass
            if insn.mnemonic == "bl":
                note = "  ; call"
            if mark or note:
                log("  0x%08x: %-8s %-46s%s%s" % (insn.address, insn.mnemonic, op, note, mark))
            seen += 1
            if seen > 400:
                break

    for t in TARGETS:
        log("\n" + "=" * 88)
        log("TARGET " + t)
        hits = strva.get(t) or []
        if not hits:
            log("  string not present")
            continue
        mine = [(pc, addr) for pc, addr in xref_hits
                if addr in [h[1] for h in hits]]
        if not mine:
            log("  no ADRP/ADD xref (referenced indirectly)")
            for off, va in hits[:3]:
                ph = [p for p in ptr_hits if p[1] == va][:6]
                for pva, sva, fl in ph:
                    log("  ptr-to-string @ 0x%x flags=%d" % (pva, fl))
        for pc, addr in mine[:6]:
            log("  xref ADRP @ 0x%x -> string 0x%x" % (pc, addr))
            disasm(pc, before=0x40, after=0x160, tag=t)

    for k in KNOWN:
        try:
            va = int(k, 16)
        except Exception:
            continue
        log("\n" + "=" * 88)
        log("KNOWN SITE " + k)
        disasm(va, before=0x40, after=0x160, tag=k)

    open(OUT, "w", encoding="utf-8", errors="replace").write("\n".join(lines))
    print("WROTE %s lines=%d" % (OUT, len(lines)))


if __name__ == "__main__":
    main()
