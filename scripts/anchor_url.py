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
    """ADRP (+ register copies) then ADD, resolving to target_va."""
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
                sh = (v >> 22) & 3
                if rn in known and sh == 0:
                    val = known[rn] + imm12
                    if val == target_va:
                        out.append((pc + IMG, TEXT_OFF + (i + j) * 4 + IMG))
                        break
                    known[rd2] = val
            elif (v & 0xFFE0FFE0) == 0xAA0003E0:      # MOV xd, xm
                rd2, rm = v & 0x1F, (v >> 16) & 0x1F
                if rm in known:
                    known[rd2] = known[rm]
                else:
                    known.pop(rd2, None)
            elif (v & 0xFF800000) in (0xD2800000, 0xF2800000, 0x92800000, 0xB2800000):
                known.pop(v & 0x1F, None)
    return out


print("### context of the 'pes22' literal ###")
off = data.find(b"pes22")
while off >= 0:
    ctx = data[max(0, off - 120):off + 160]
    print("  file 0x%x  va 0x%x" % (off, off + IMG))
    print("     %r" % ctx)
    print("     -> code sites: %s" % sites(off + IMG))
    off = data.find(b"pes22", off + 1)
    if off > 0xC00000:
        break

print()
print("### context around the JNI method-name literal AddRequestHeader (0xaab5ce) ###")
a = data.rfind(b"\x00", 0, 0xaab5ce)
b = 0xaab5ce
seg = data[a + 1:a + 1 + 400]
print("  siblings: %r" % seg)

print()
print("### does native pass a body to Java? JNI names around HttpImpl (0xb1d462) ###")
h = data.rfind(b"\x00", 0, 0xb1d462)
print("  ctx: %r" % data[h + 1:h + 1 + 400])
