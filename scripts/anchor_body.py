import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = "efootball-apk/native/lib/arm64-v8a/libUE4.so"
IMG = 0x100000
TEXT_OFF, TEXT_END = 0x28293C0, 0x8C35207
data = open(SO, "rb").read()
code = data[TEXT_OFF:TEXT_END]
n = len(code) // 4
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def fo(va):
    return va - IMG


def cstr(f, n=96):
    if f < 0 or f >= len(data):
        return None
    out = b""
    for k in range(n):
        c = data[f + k]
        if c == 0:
            break
        if c < 0x20 or c > 0x7E:
            return None
        out += bytes([c])
    return out.decode() if len(out) >= 3 else None


def sites(target_va, window=16):
    PAGE = target_va & ~0xFFF
    out = []
    for i in range(n):
        w = struct.unpack_from("<I", code, i * 4)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 0x3)
        if imm & 0x100000:
            imm -= 0x200000
        rd = w & 0x1F
        pc = TEXT_OFF + i * 4
        if ((pc + IMG) & ~0xFFF) + (imm << 12) != PAGE:
            continue
        known = {rd: PAGE}
        for j in range(1, window + 1):
            if i + j >= n:
                break
            v = struct.unpack_from("<I", code, (i + j) * 4)[0]
            if (v & 0xFF000000) == 0x91000000:
                rd2, rn, imm12 = v & 0x1F, (v >> 5) & 0x1F, (v >> 10) & 0xFFF
                if rn in known and ((v >> 22) & 3) == 0:
                    val = known[rn] + imm12
                    if val == target_va:
                        out.append((pc + IMG, TEXT_OFF + (i + j) * 4 + IMG))
                        break
                    known[rd2] = val
            elif (v & 0xFFE0FFE0) == 0xAA0003E0:
                rd2, rm = v & 0x1F, (v >> 16) & 0x1F
                if rm in known:
                    known[rd2] = known[rm]
                else:
                    known.pop(rd2, None)
            elif (v & 0xFF800000) in (0xD2800000, 0xF2800000, 0x92800000, 0xB2800000):
                known.pop(v & 0x1F, None)
    return out


def show(title, start, size):
    print("=" * 78)
    print(title)
    print("=" * 78)
    adrp = {}
    for ins in md.disasm(data[fo(start):fo(start) + size], start):
        line = "  0x%08x  %-5s %s" % (ins.address, ins.mnemonic, ins.op_str)
        if ins.mnemonic == "adrp":
            c = [x.strip() for x in ins.op_str.split(",")]
            try:
                adrp[c[0]] = int(c[1].lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add":
            c = [x.strip() for x in ins.op_str.split(",")]
            if len(c) == 3 and c[1] in adrp:
                try:
                    t = adrp[c[1]] + int(c[2].lstrip("#"), 16)
                    adrp[c[0]] = t
                    s = cstr(fo(t))
                    if s:
                        line += "\n         -> 0x%08x  %r" % (t, s)
                except Exception:
                    pass
        elif ins.mnemonic in ("bl", "b"):
            line += "   ; CALL"
        print(line)
    print()


literals = [b"application/octet-stream", b"Content-Encoding", b"gzip",
            b"Content-Type", b"Authorization", b"Cookie"]
for lit in literals:
    k = data.find(lit)
    if k < 0:
        print("%-24r not found" % lit)
        continue
    st = sites(k + IMG)
    print("%-24r file 0x%x  va 0x%x  -> %d site(s): %s"
          % (lit, k, k + IMG, len(st), ["0x%x" % a for a, b in st[:6]]))
print()

for lit in (b"application/octet-stream", b"Content-Encoding"):
    k = data.find(lit)
    if k < 0:
        continue
    st = sites(k + IMG)
    if st:
        show("first site using %r  (va 0x%x)" % (lit, st[0][0]),
             st[0][0] - 0x100, 0x220)
