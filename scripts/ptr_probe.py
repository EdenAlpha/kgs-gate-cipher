"""Establish whether this libUE4.so carries usable absolute/relocated pointers
at all, so the all-zero vtables mean what I think they mean.

Three facts were in tension:
  * .rela.dyn at 0x2ed270 is present and DT_RELAENT says 24, but every one of
    its 169,027 entries has an implausible r_offset (find_bf.py).
  * the four vtables in .data.rel.ro read as all zeros.
  * DT_INIT_ARRAY points at 0x98bd898 with size 0x171a8 (11,829 entries),
    which only works if those pointers are readable.

If e_type is ET_EXEC the image is fixed-address and needs no relative
relocations at all -- but then .init_array and .data.rel.ro should be populated
in the file.  If e_type is ET_DYN they need relocations, which are missing.
Whichever way this falls tells us whether the zero vtables are a real absence
or a mis-read address on my part.
"""
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
d = open(SO, "rb").read()

e_type = struct.unpack_from("<H", d, 0x10)[0]
print("e_type: %d  (%s)" % (e_type,
                            {2: "ET_DYN (PIC, needs relocations)",
                             3: "ET_EXEC (fixed address)"}.get(e_type, "?")))
print("e_entry: 0x%x" % struct.unpack_from("<Q", d, 0x18)[0])
print("PIE/dynamic: first PT_LOAD vaddr=0x%x offset=0x%x"
      % (struct.unpack_from("<IIQQQQQQ", d, 0x40)[3],
         struct.unpack_from("<IIQQQQQQ", d, 0x40)[2]))

# --- .init_array -----------------------------------------------------------
IA_OFF, IA_ADDR, IA_SIZE = 0x98B5898, 0x98BD898, 0x171A8
print("\n=== .init_array  va=0x%x off=0x%x size=0x%x (%d entries) ==="
      % (IA_ADDR, IA_OFF, IA_SIZE, IA_SIZE // 8))
vals = [struct.unpack_from("<Q", d, IA_OFF + i * 8)[0] for i in range(16)]
for i, v in enumerate(vals):
    print("  [%2d] 0x%016x" % (i, v))
print("  non-zero in first 256 entries: %d/%d"
      % (sum(1 for i in range(256)
             if struct.unpack_from("<Q", d, IA_OFF + i * 8)[0]),
         256))
print("  plausible code VAs (0x28293c0..0x8b35200): %d/%d"
      % (sum(1 for i in range(256)
             if 0x28293C0 <= struct.unpack_from("<Q", d, IA_OFF + i * 8)[0]
             < 0x8B35200), 256))

# --- .got ------------------------------------------------------------------
print("\n=== .got  va=0x98d4c60 off=0x98ccc60 ===")
for i in range(8):
    v = struct.unpack_from("<Q", d, 0x98CCC60 + i * 8)[0]
    print("  [%d] 0x%016x" % (i, v))

# --- the vtables themselves ------------------------------------------------
print("\n=== vtable candidates in .data.rel.ro (off = va - 0x8000) ===")
for tag, va in (("cipher state final", 0x981A620),
                ("cipher state alt", 0x981A5B0),
                ("context A", 0x981A590),
                ("context B", 0x981A4A0)):
    o = va - 0x8000
    vals = [struct.unpack_from("<Q", d, o + i * 8)[0] for i in range(8)]
    print("  %-22s va=0x%x off=0x%x" % (tag, va, o))
    print("      %s" % " ".join("%016x" % v for v in vals))

# --- is the .rela.dyn region really what it claims? ------------------------
print("\n=== .rela.dyn region: first 64 bytes and entropy-ish ===")
reg = d[0x2ED270:0x2ED270 + 64]
print("  %s" % reg.hex())
print("  distinct bytes in 4096: %d" % len(set(d[0x2ED270:0x2ED270 + 4096])))

# --- .rela.plt (parsed fine) as the control -------------------------------
print("\n=== .rela.plt control (file 0x6cb8d0, 24-byte entries) ===")
for i in range(4):
    r_off, r_info, r_add = struct.unpack_from("<QQq", d, 0x6CB8D0 + i * 24)
    print("  off=0x%012x info=0x%016x type=%u addend=0x%x"
          % (r_off, r_info, r_info & 0xFFFFFFFF, r_add))

# --- does anything anywhere in .data.rel.ro look populated? ---------------
print("\n=== scan .data.rel.ro for non-zero qwords (first 40) ===")
n = 0
o = 0x8B6D140
end = 0x8B6D140 + 0xD48748
found = 0
while o + 8 <= end and found < 40:
    v = struct.unpack_from("<Q", d, o)[0]
    if v:
        print("  va=0x%08x  0x%016x" % (o + 0x8000, v))
        found += 1
    o += 8
print("  non-zero qwords found in first %d bytes: %d"
      % (o - (0x8B6D140), found))
