"""vtable_scan.py -- who installs the log sink?

Chain established so far:
    "Score  HOME[%d] AWAY[%d]\n" @0xbaa312
      -> bl 0x39e5ff8   (variadic emitter, 678 call sites)
           ldr x8,[0x9c14870]   (.bss, starts NULL -> cbz = silent)
           blr x8
    0x9c14870 written by exactly one setter, 0x39e5fdc, which is reached
    only from the thunk at 0x3a05918 (mov x0,x1; mov x1,x2; b setter),
    i.e. a member-function thunk that drops a leading context argument.

Thunk has no PC-relative callers -> it must be a vtable slot.  In a shared
object the slot value lives in .rela.dyn as an R_AARCH64_RELATIVE addend,
so the file itself holds 0 and a plain abs64 scan finds nothing.

Finds that vtable, then reports which slots sit beside it.
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

e_shoff = struct.unpack_from("<Q", d, 40)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 58)
sho = e_shoff + e_shstrndx * e_shentsize
str_off = struct.unpack_from("<Q", d, sho + 24)[0]
str_size = struct.unpack_from("<Q", d, sho + 32)[0]
strtab = d[str_off:str_off + str_size]

secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    nmoff = struct.unpack_from("<I", d, o)[0]
    t = struct.unpack_from("<I", d, o + 4)[0]
    off = struct.unpack_from("<Q", d, o + 24)[0]
    size = struct.unpack_from("<Q", d, o + 32)[0]
    entsz = struct.unpack_from("<Q", d, o + 56)[0]
    nm = strtab[nmoff:strtab.find(b"\x00", nmoff)].decode("ascii", "replace")
    secs.append((nm, t, off, size, entsz))

THUNK = 0x3A05918
LO, HI = 0x3A05880, 0x3A05A20

print("=" * 78)
print("R_AARCH64_RELATIVE addends pointing into the thunk block")
print("=" * 78)
R_RELATIVE, R_ABS64 = 1027, 257
hits = []
for nm, t, off, size, entsz in secs:
    if t != 4 or not entsz:
        continue
    for k in range(size // entsz):
        o = off + k * entsz
        r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
        r_type = r_info & 0xFFFFFFFF
        if r_type in (R_RELATIVE, R_ABS64) and LO <= r_add <= HI:
            hits.append((r_off, r_add, nm, r_type))
hits.sort()
print("  %d reloc addends in [0x%x, 0x%x]   (RELATIVE=1027 ABS64=257)"
      % (len(hits), LO, HI))
for r_off, r_add, nm, r_type in hits:
    mark = "   <== THUNK 0x3a05918 (setter shim)" if r_add == THUNK else ""
    print("    slot=0x%-10x addend=0x%-9x type=%-5d (%s)%s"
          % (r_off, r_add, r_type, nm, mark))

thunk_slot = None
for r_off, r_add, nm in hits:
    if r_add == THUNK:
        thunk_slot = r_off
        break

if thunk_slot is None:
    print("\n  thunk NOT in any reloc -> it is not a vtable entry")
    sys.exit(0)

# the vtable is the run of slots around it
print()
print("=" * 78)
print("the vtable containing slot 0x%x" % thunk_slot)
print("=" * 78)
vt_lo = thunk_slot - 16 * 8
vt_hi = thunk_slot + 16 * 8
around = [(r_off, r_add) for r_off, r_add, nm in hits
          if vt_lo <= r_off <= vt_hi]
around.sort()
# widen: find every reloc addend in a contiguous run of slots near thunk_slot
allrel = {}
for nm, t, off, size, entsz in secs:
    if t != 4 or not entsz:
        continue
    for k in range(size // entsz):
        o = off + k * entsz
        r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
        if (r_info & 0xFFFFFFFF) == R_RELATIVE:
            allrel[r_off] = r_add

base = thunk_slot & ~7
lo = hi = base
while (lo - 8) in allrel:
    lo -= 8
while (hi + 8) in allrel:
    hi += 8
print("  contiguous reloc run: 0x%x .. 0x%x  (%d slots)"
      % (lo, hi, (hi - lo) // 8 + 1))
for a in range(lo, hi + 1, 8):
    v = allrel.get(a)
    mark = "  <== setter thunk" if v == THUNK else ""
    print("    [0x%x] = 0x%x%s" % (a, v, mark))
