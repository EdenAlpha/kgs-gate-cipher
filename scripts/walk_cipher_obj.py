"""Walk the cipher-object builder and the encrypt wrapper to the real algorithm.

What the previous walk settled
------------------------------
vtable[5] transform loops over 8-byte blocks doing
    swap32x2 -> cipher[6] -> swap32x2
and vtable[7] / vtable[8] are PKCS#7 pad/unpad at block size 8.  So the block
size, the padding and the byte order are known.  What is *not* known is which
block cipher runs inside the object, and where the IV enters.

That object is built by vtable[11] = 0x7b2d164 on every transform, and it owns
the vtable holding the encrypt (slot 6) and decrypt (slot 7) entries.  So this
walks:

    0x7b2d164   vtable[11]  -- builds the cipher object (finds its vtable)
    0x7b2e150   -- called as (new(0x1058), &iv, 8); 0x1058 = 4184 bytes
    0x7b2cbb0   mode-0 encrypt wrapper (pad -> transform -> prepend IV)
    0x7b2ca78   the (state, state, data, len, out) helper

and then resolves whatever vtable 0x7b2d164 stores, because that is where the
algorithm actually is.  Constants are folded to '-> 0x<va>' as before, and the
byte-swap helpers are called out by name so the output reads as structure
rather than as raw opcodes.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\walk_cipher_obj.txt"

d = open(SO, "rb").read()

e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
SEC = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    SEC.append({"name": nm, "type": s[1], "flags": s[2], "addr": s[3],
                "off": s[4], "size": s[5]})

TEXT = [s for s in SEC if s["name"] == ".text"][0]
TVA, TSZ, TOFF = TEXT["addr"], TEXT["size"], TEXT["off"]

# known helpers, named so the listing reads as structure
NAMED = {
    0x7B2D354: "byte_swap_block(in -> tmp)",
    0x7B2D398: "byte_swap_block(tmp -> out)",
    0x7B2D3DC: "get_iv_ptr -> &state+0x4c",
    0x7B2D3E4: "get_iv_len -> 8",
    0x7B2D144: "set_iv(state, iv, 8)",
    0x7B2D164: "build_cipher_object(state)",
    0x7B2C7EC: "pkcs7_pad(str, block)",
    0x7B2C88C: "pkcs7_unpad(str, block)",
    0x7B2CE94: "transform(state, in, len, out, &n)",
    0x7B2CF9C: "transform_dec(state, in, len, out, &n)",
    0x7B2D094: "init_cipher_state(state, key, keylen)",
    0x7B2CBB0: "encrypt_mode0",
    0x7B2BF14: "encrypt_mode1",
    0x7B2CA78: "pad_then_transform(state, data, len, out)",
}

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


def window(va, before, after):
    lo = max(TVA, va - before)
    hi = min(TVA + TSZ, va + after)
    start = lo - (lo - va) % 4
    o = TOFF + (start - TVA)
    return list(md.disasm(d[o:o + (hi - start)], start))


TARGETS = [
    (0x7B2D164, "vtable[11]  build cipher object (owns the real vtable)"),
    (0x7B2E150, "called (new(0x1058), &iv, 8) from inside the builder"),
    (0x7B2CBB0, "encrypt_mode0  pad -> transform -> prepend 8 bytes"),
    (0x7B2CA78, "pad_then_transform(state, data, len, out)"),
]

for va, label in TARGETS:
    say("=" * 78)
    say("%s   @ 0x%x" % (label, va))
    say("=" * 78)
    body = window(va, 0x30, 0x600)
    pend = {}
    started = False
    for ins in body:
        mark = ""
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            p = pend.pop(ins.address - 4)
            try:
                im = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                mark = "   -> 0x%x" % (p + im)
            except Exception:
                pass
        if ins.mnemonic in ("bl", "b"):
            try:
                t = int(ins.op_str.lstrip("#"), 16)
                mark = "   -> 0x%x %s" % (t, NAMED.get(t, ""))
            except Exception:
                pass
        if ins.address == va:
            mark += "   <<<< ENTRY"
            started = True
        if not started:
            continue
        say("      0x%08x  %-8s %-42s%s"
            % (ins.address, ins.mnemonic, ins.op_str, mark))
        if ins.mnemonic == "ret":
            say("      <<<<")
            break
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
