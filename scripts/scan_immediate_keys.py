"""Find keys assembled from ARM64 immediates rather than stored as bytes.

Why this hypothesis: two full sweeps of libUE4.so (160,822,937 offsets, under
a printable oracle and then a PKCS#7 oracle) both returned NO, so the key is
not 32 contiguous bytes anywhere in the file.  The one idiom already proven to
hide data from every string/byte search in this binary is immediate
materialisation -- the sign seed, CLOCK_BOOTTIME and /dev/urandom were all
recovered by reading MOV/MOVK/MOVN operands, never by scanning bytes.

This decodes the immediates straight out of the instruction words with numpy
(no disassembler, so it covers all 103 MB of .text in seconds), reassembles the
register each MOVZ starts, and tests every 16/24/32-byte result as an AES key
against the recorded gate replies using the validated PKCS#7 oracle.

Encoding used (Arm ARM C6.2):
    MOVZ  sf=1 0b110100101 -> 0xd2800000     MOVZ  sf=0 -> 0x52800000
    MOVK  sf=1 0b111100101 -> 0xf2800000     MOVK  sf=0 -> 0x72800000
    imm16 = bits[20:5]   hw = bits[22:21] (= byte offset/2)   Rd = bits[4:0]
"""
import re
import struct
import sys
import time

import numpy as np
from Crypto.Cipher import AES

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\scan_immediate_keys.txt"

d = open(SO, "rb").read()

# --------------------------------------------------------------- sections ---
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
text = None
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    if nm == ".text":
        text = {"addr": s[3], "off": s[4], "size": s[5]}
print(".text va 0x%x off 0x%x size %d" % (text["addr"], text["off"], text["size"]))
sys.stdout.flush()

raw = d[text["off"]:text["off"] + text["size"]]
if len(raw) % 4:
    raw += b"\x00" * (4 - len(raw) % 4)
w = np.frombuffer(raw, dtype="<u4")

MOVZ64, MOVZ32 = 0xD2800000, 0x52800000
MOVK64, MOVK32 = 0xF2800000, 0x72800000

is_movz = ((w & 0xFF800000) == MOVZ64) | ((w & 0xFF800000) == MOVZ32)
is_movk = ((w & 0xFF800000) == MOVK64) | ((w & 0xFF800000) == MOVK32)
print("MOVZ: %d   MOVK: %d" % (int(is_movz.sum()), int(is_movk.sum())))
sys.stdout.flush()

# ------------------------------------------------------------ reassemble ----
# Walk once.  A MOVZ starts a register; following MOVKs to the same Rd fill its
# other halves.  A gap or a new MOVZ ends the group.
idx_z = np.nonzero(is_movz)[0]
imm_all = (w >> 5) & 0xFFFF
hw_all = (w >> 21) & 3
rd_all = w & 0x1F
sf_all = (w >> 31) & 1

# map: register index -> current partial value, keyed by position window
MAX_GAP = 12          # instructions allowed between MOVZ and its last MOVK
groups = []           # (start_idx, {hw: bytes}, rd, sf)
cur = None
last_i = -999

# iterate over movz and movk positions in address order
events = np.nonzero(is_movz | is_movk)[0]
for i in events.tolist():
    i = int(i)
    if is_movz[i]:
        if cur is not None:
            groups.append(cur)
        cur = {"start": i, "rd": int(rd_all[i]), "sf": int(sf_all[i]),
               "parts": {int(hw_all[i]): int(imm_all[i])}}
        last_i = i
    else:
        if cur is None:
            continue
        if i - last_i > MAX_GAP or int(rd_all[i]) != cur["rd"]:
            groups.append(cur)
            cur = None
            continue
        cur["parts"][int(hw_all[i])] = int(imm_all[i])
        last_i = i
if cur is not None:
    groups.append(cur)

print("register groups: %d" % len(groups))
sys.stdout.flush()


def assemble(g):
    parts = g["parts"]
    if not parts:
        return None
    hwmax = max(parts)
    nbytes = (hwmax + 1) * 2
    if nbytes > 64:
        return None
    buf = bytearray(nbytes)
    for hw, imm in parts.items():
        b = imm.to_bytes(2, "little")
        buf[hw * 2:hw * 2 + 2] = b
    return bytes(buf)


# A key almost never lives in one register: the usual idiom is
#     movz x0,#.. movk x0,..16 movk x0,..32 movk x0,..48
#     movz x1,#.. movk x1,..16 movk x1,..32 movk x1,..48
#     stp x0, x1, [..]
# i.e. 8 bytes per register, stored as a pair.  Grouping strictly per register
# therefore only ever yields 8-byte fragments -- which is exactly why the first
# run of this script tested *zero* candidates.  Chain neighbours that sit close
# together in the instruction stream and take every 16/24/32-byte combination.
sizes = {}
regs = []
for g in groups:
    b = assemble(g)
    if b is None:
        continue
    sizes[len(b)] = sizes.get(len(b), 0) + 1
    regs.append((g["start"], b))
regs.sort(key=lambda t: t[0])

print("  register-value sizes: %s"
      % dict(sorted(sizes.items(), key=lambda t: -t[1])[:10]))

cands = {16: set(), 24: set(), 32: set()}
for s, b in regs:
    if len(b) in cands:
        cands[len(b)].add(b)

MAX_CHAIN_GAP = 10        # words between the start of one reg and the next
n = len(regs)
for i in range(n):
    total = bytearray(regs[i][1])
    last_end = regs[i][0]
    j = i + 1
    while j < n and len(total) < 32:
        if regs[j][0] - last_end > MAX_CHAIN_GAP:
            break
        nb = regs[j][1]
        if len(total) + len(nb) > 32:
            break
        total += nb
        last_end = regs[j][0] + 1
        if len(total) in cands:
            cands[len(total)].add(bytes(total))
        j += 1

for k in sorted(cands):
    print("  %d-byte candidates: %d distinct   (all-ASCII: %d)"
          % (k, len(cands[k]),
             sum(1 for v in cands[k] if all(0x20 <= c < 0x7F for c in v))))
print("  chained from %d register values, gap<=%d words"
      % (len(regs), MAX_CHAIN_GAP))
sys.stdout.flush()

# ------------------------------------------------------------- the oracle ---
rawlog = open(LOG, "rb").read().split(b"\n")
gate, path = [], None
for line in rawlog:
    if line.startswith(b"### RESP ") or line.startswith(b"### REQ "):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
    elif line.startswith(b"RESPHEX: "):
        try:
            b = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            b = None
        if b is not None and path and "/gate/" in path:
            gate.append(b)
        path = None
gate.sort(key=len, reverse=True)
targets = [b for b in gate if len(b) >= 64][:6]
print("")
print("oracle: PKCS#7 on all %d gate replies, lengths %s"
      % (len(targets), [len(t) for t in targets]))


def pad_ok(block):
    n = block[15]
    return 1 <= n <= 16 and block[16 - n:] == bytes([n]) * n


def xor16(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")


def opens(key):
    ec = AES.new(key, AES.MODE_ECB)
    for lay in (1, 2):
        ok = True
        for r in targets:
            prev, last = ((r[-32:-16], r[-16:]) if lay == 1
                          else (r[-48:-32], r[-32:-16]))
            if not pad_ok(xor16(ec.decrypt(last), prev)):
                ok = False
                break
        if ok:
            return lay
    return None


hits = []
t0 = time.time()
tested = 0
for klen in sorted(cands):
    for v in sorted(cands[klen]):
        tested += 1
        lay = opens(v)
        if lay:
            hits.append((klen, v, lay))
            print("  HIT len=%d layout=%d key=%s" % (klen, lay, v.hex()),
                  flush=True)
print("")
print("tested %d assembled candidates in %.1f s" % (tested, time.time() - t0))
print("hits: %d" % len(hits))
if hits:
    print("YES -- key assembled from immediates")
    for klen, v, lay in hits:
        print("   len %d layout %d  %s" % (klen, lay, v.hex()))
else:
    print("NO -- no 16/24/32-byte value materialised from MOVZ/MOVK immediates "
          "opens every recorded gate reply")

with open(OUT, "w", encoding="utf-8") as f:
    f.write(".text va 0x%x size %d\n" % (text["addr"], text["size"]))
    f.write("MOVZ %d  MOVK %d  groups %d\n"
            % (int(is_movz.sum()), int(is_movk.sum()), len(groups)))
    for k in sorted(cands):
        f.write("  %d-byte candidates: %d (ascii %d)\n"
                % (k, len(cands[k]),
                   sum(1 for v in cands[k] if all(0x20 <= c < 0x7F for c in v))))
    f.write("tested %d\n" % tested)
    f.write("hits %d\n" % len(hits))
    for klen, v, lay in hits:
        f.write("HIT len=%d layout=%d %s\n" % (klen, lay, v.hex()))
print("wrote %s" % OUT)
