"""Who WRITES the encryption-context pointer at 0xa4a98d8?

Chain (walk_enc2.txt):
    0x7b2ca38  adrp x8,#0xa4a9000 ; ldr x0,[x8,#0x8d8] ; ret   <- getter
    0x7b2ca44  vtable[1](*0xa4a98d8) ; *0xa4a98d8 = 0           <- destructor
    0x7b2c9bc  ldr x19,[x23,#0x8d8]                             <- initializer
                _Znwm(0x38)  -> allocates the context (key at +0x08)

Three adrp-reachable accesses, but only the destructor STOREs -- and it
stores zero.  So the real store must be in a shape not yet matched.

Previous scan missed:
  * STP/LDP  (pair) -- the pointer can be the 2nd half of a pair, e.g.
    stp x0,x1,[x8,#0x8d0] writes 0xa4a98d0 AND 0xa4a98d8
  * pre/post-index str
  * any executable section other than .text

This version matches all of those, across every executable section, keeps
only .data/.bss targets, and then disassembles the candidates to confirm.
"""
import struct

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\find_ctx.txt"

TARGET = 0xA4B0158
LO, HI = 0xA4B0140, 0xA4B0190
RNG_LO, RNG_HI = 0x9900000, 0xC000000     # .data / .bss
MAXK = 64

d = open(SO, "rb").read()
FL = len(d)

e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
SECS = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    SECS.append({"name": nm, "type": s[1], "flags": s[2], "addr": s[3],
                 "off": s[4], "size": s[5], "entsize": s[9]})
by = {s["name"]: s for s in SECS}

SHF_EXEC = 0x4
execs = [s for s in SECS if s["flags"] & SHF_EXEC and s["size"] > 16]
print("executable sections: %s"
      % ", ".join("%s@0x%x(%d)" % (s["name"], s["addr"], s["size"])
                  for s in execs))

hits = []

for sec_ in execs:
    raw = d[sec_["off"]:sec_["off"] + sec_["size"]]
    if len(raw) % 4:
        raw += b"\x00" * (4 - len(raw) % 4)
    w = np.frombuffer(raw, dtype="<u4")
    n = len(w)
    if n < 4:
        continue

    # ADRP Xd, label
    is_adrp = (w & 0x9F000000) == 0x90000000
    # ldr/str, unsigned immediate, GPR          size(2) 111 0 01 opc imm12 Rn Rt
    is_ls = (w & 0x3F000000) == 0x39000000
    # ldp/stp, unsigned immediate               opc 101 0 00 ... (bits31-30 free)
    is_pair = (w & 0x3F000000) == 0x28000000
    # load/store register, pre/post-index: size 111 0 00 opc 01 imm9 xx Rn Rt
    #   bits 11-10 = 11 (pre, updates the base reg) or 01 (post)
    is_pp = ((w & 0x3F300000) == 0x38100000) & (((w >> 10) & 0x3) != 0)
    is_pre = is_pp & (((w >> 10) & 0x3) == 0x3)
    is_post = is_pp & (((w >> 10) & 0x3) == 0x1)
    is_st = is_ls | is_pair | is_pre | is_post
    is_add = (w & 0xFFC00000) == 0x91000000

    idx = np.nonzero(is_adrp)[0]
    if not len(idx):
        continue
    rd_a = (w[idx] & 0x1F).astype(np.int64)
    immlo = (w[idx] >> 29) & 0x3
    immhi = (w[idx] >> 5) & 0x7FFFF
    raw21 = ((immhi << 2) | immlo).astype(np.int64)
    signed = np.where(raw21 >= (1 << 20), raw21 - (1 << 21), raw21)
    pages = ((sec_["addr"] + idx.astype(np.int64) * 4) & ~0xFFF) + (signed << 12)

    cur_reg = rd_a.copy()
    cur_addr = pages.copy()
    alive = np.ones(len(idx), dtype=bool)

    for k in range(1, MAXK + 1):
        j = idx + k
        jj = np.minimum(j, n - 1)
        ok = (j < n) & alive
        wj = w[jj]
        rn = (wj >> 5) & 0x1F
        rt = wj & 0x1F

        m_ls = ok & is_ls[jj] & (rn == cur_reg)
        m_pr = ok & (is_pair | is_pre | is_post)[jj] & (rn == cur_reg)
        m_add = ok & is_add[jj] & (rn == cur_reg) & (rt == cur_reg)

        if m_ls.any():
            pos = np.nonzero(m_ls)[0]
            inst = wj[pos]
            scale = np.left_shift(np.int64(1),
                                  ((inst >> 30) & 0x3).astype(np.int64))
            imm12 = ((inst >> 10) & 0xFFF).astype(np.int64)
            opc = (inst >> 22) & 0x3
            kind = np.where(opc == 0, "STORE",
                            np.where(opc == 1, "LOAD",
                                     np.where(opc == 2, "LDRSW/PRFM", "OTHER")))
            tgt = cur_addr[pos] + imm12 * scale
            keep = (tgt >= RNG_LO) & (tgt < RNG_HI)
            for q in np.nonzero(keep)[0]:
                hits.append((int(sec_["addr"] + int(j[pos[q]]) * 4),
                             int(tgt[q]), str(kind[q])))
            rt_pos = rt[pos] == cur_reg[pos]
            alive[pos[rt_pos]] = False

        if m_pr.any():
            pos = np.nonzero(m_pr)[0]
            inst = wj[pos]
            opc2 = (inst >> 30) & 0x3               # 10 -> 64-bit
            sc = np.where(opc2 == 2, np.int64(8), np.int64(4))
            pair = is_pair[pos]
            # unsigned pair: imm7 at bits 21-15, scaled
            immpair = ((((inst >> 15) & 0x7F).astype(np.int64)
                        << np.int64(56)) >> np.int64(56)) * sc
            # pre/post: imm9 at bits 20-12, signed
            imm9 = ((((inst >> 12) & 0x1FF).astype(np.int64)
                     << np.int64(55)) >> np.int64(55))
            offs = np.where(pair, immpair, imm9)
            opc = (inst >> 22) & 0x3
            isload = (pair & (opc == 1)) | (~pair & np.isin(opc, (1, 2, 3)))
            kind = np.where(isload, "LOAD", "STORE")
            addrs = cur_addr[pos]
            for q, p in enumerate(pos):
                base = int(addrs[q]) + int(offs[q])
                va = int(sec_["addr"] + int(j[p]) * 4)
                if RNG_LO <= base < RNG_HI:
                    hits.append((va, base, str(kind[q])))
                if pair[q] and RNG_LO <= base + int(sc[q]) < RNG_HI:
                    hits.append((va, base + int(sc[q]), str(kind[q]) + "+8"))
            # pre-index updates the base register itself
            pre = is_pre[pos]
            for q, p in enumerate(pos):
                if pre[q]:
                    cur_addr[p] = int(addrs[q]) + int(offs[q])
            rt_pos = rt[pos] == cur_reg[pos]
            alive[pos[rt_pos]] = False

        if m_add.any():
            pos = np.nonzero(m_add)[0]
            inst = wj[pos]
            imm12 = ((inst >> 10) & 0xFFF).astype(np.int64)
            sh = ((inst >> 22) & 1).astype(np.int64)
            addrs = cur_addr[pos]
            for q, p in enumerate(pos):
                cur_addr[p] = int(addrs[q]) + int(imm12[q]) * (
                    4096 if int(sh[q]) else 1)

        writes = ((wj & 0x1F) == cur_reg) & ~m_ls & ~m_pr & ~m_add & ok
        alive[writes] = False

print("accesses collected in .data/.bss: %d" % len(hits))

near = sorted([h for h in hits if LO <= h[1] < HI], key=lambda t: (t[1], t[0]))
exact = [h for h in hits if h[1] == TARGET]
print("in window 0x%x..0x%x : %d" % (LO, HI, len(near)))
print("to EXACTLY 0x%x      : %d" % (TARGET, len(exact)))

# ---------------------------------------------------------- symbol names ----
plt, rela = by[".plt"], by[".rela.plt"]
dynsym, dynstr = by[".dynsym"], by[".dynstr"]


def sym_name(i):
    off = dynsym["off"] + i * dynsym["entsize"]
    st_name = struct.unpack_from("<I", d, off)[0]
    b = dynstr["off"] + st_name
    return d[b:d.index(b"\x00", b)].decode("ascii", "replace")


reloc = {}
for i in range(rela["size"] // 24):
    _o, r_info, _ = struct.unpack_from("<QQq", d, rela["off"] + i * 24)
    reloc[i] = sym_name(r_info >> 32)


def plt_name(va):
    if va < plt["addr"] or va > plt["addr"] + plt["size"]:
        return None
    return reloc.get((va - plt["addr"] - 0x20) // 16)


def _delta(va):
    if va >= 0x9906CC0:
        return 0xC000
    if va >= 0x8B75140:
        return 0x8000
    if va >= 0x28293C0:
        return 0x4000
    return 0x0


def word(va):
    o = va - _delta(va)
    if 0 <= o + 4 <= FL:
        return struct.unpack_from("<I", d, o)[0]
    return None


def read_str(va, n=56):
    o = va - _delta(va)
    if 0 <= o < FL:
        b = d[o:o + n]
        e = b.find(b"\x00")
        if e >= 0:
            b = b[:e]
        if b and all(0x20 <= c < 0x7F for c in b):
            return repr(b.decode("ascii"))
        if b:
            return "<%d bytes> %s" % (len(b), b[:16].hex())
        return "<zeroed>"
    return "<not file-backed>"


RET = 0xD65F03C0


def func_start(site, back=0x8000):
    for va in range(site & ~3, (site & ~3) - back, -4):
        if word(va) == RET:
            return va + 4
    return None


md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


say("=" * 78)
say("EVERY adrp-REACHABLE ACCESS TO 0x%x..0x%x" % (LO, HI))
say("=" * 78)
say("executable sections scanned: %d" % len(execs))
say("accesses in window         : %d" % len(near))
say("")
for va, tgt, kind in near:
    mark = "   <<<< CONTEXT POINTER" if tgt == TARGET else ""
    say("  0x%08x  %-10s -> 0x%08x%s" % (va, kind, tgt, mark))


def walk(va, tag, extra=0x140):
    st = func_start(va)
    say("")
    say("-" * 78)
    say("%s 0x%08x" % (tag, va))
    if st is None:
        say("  no enclosing function found")
        return
    say("  function start 0x%x  (%d bytes before)" % (st, va - st))
    insns = list(md.disasm(d[st - 0x4000:va - 0x4000 + extra], st))
    say("  --- calls / strings ---")
    pend = {}
    for i, ins in enumerate(insns):
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            page = pend.pop(ins.address - 4)
            try:
                imm = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                say("      [ref] 0x%08x -> 0x%08x  %s"
                    % (ins.address, page + imm, read_str(page + imm)))
            except Exception:
                pass
        if ins.mnemonic in ("bl", "blr"):
            nm = None
            if ins.mnemonic == "bl":
                try:
                    nm = plt_name(int(ins.op_str.lstrip("#"), 16))
                except Exception:
                    pass
            say("      0x%08x %s %s%s"
                % (ins.address, ins.mnemonic, ins.op_str,
                   ("   PLT: %s" % nm) if nm else ""))
            say("            setup: %s"
                % "; ".join("%s %s" % (c.mnemonic, c.op_str)
                            for c in insns[max(0, i - 3):i]))
    say("  --- window around the access ---")
    for ins in insns:
        if abs(ins.address - va) <= 0x50:
            say("      0x%08x  %-7s %s%s"
                % (ins.address, ins.mnemonic, ins.op_str,
                   "   <== %s" % tag if ins.address == va else ""))


say("")
say("=" * 78)
say("DETAIL: EVERY ACCESS TO THE CONTEXT POINTER 0x%x" % TARGET)
say("=" * 78)
for va, tgt, kind in exact:
    walk(va, kind)

say("")
say("=" * 78)
say("DETAIL: NEIGHBOURING GLOBALS IN THE CONTEXT BLOCK")
say("=" * 78)
for va, tgt, kind in near:
    if tgt == TARGET:
        continue
    walk(va, kind)

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
