# kgs-gate-cipher

Recovered gate-body cipher for the eFootball / PeerLink `pes22-game.cs.konami.net`
gate, plus the tooling and proofs that produced it.

Everything below was read out of the shipped `libUE4.so` (static reverse
engineering) and then confirmed against 42 real captured gate messages —
all 42 decrypt, decompress and parse with the recovered key.

---

## 1. The key is generated, not negotiated

The program hides two byte blobs inside its own `.rodata` and decodes them at
startup with a fixed recipe. No server input, no login data, no timer — so the
key is the same for every run, every session, every player of this build.

```
key[i] = src[i]  XOR  T1[i mod 9]  XOR  T2[i mod 12]  XOR  0x75
```

* `T1 = 91969a94969a9398a0`  (9 bytes)
* `T2 = 586c7e39282e392b292b2f19`  (12 bytes)
* generator: VA `0x7d64fb0`; loop A bound `#0x38` (56) → buffer `0xa4b0158`,
  loop B bound `#0x20` (32) → buffer `0xa4b0170`
* hidden sources: `.rodata 0x9823af8` (56 B) and `.rodata 0x9823ba8` (32 B)

That yields two keys:

| key | size | buffer | used by |
|-----|------|--------|---------|
| **Key A** | 56 B = Blowfish max key | `0xa4b0158` | mode 0 (Blowfish, 8-byte blocks) |
| **Key B** | 32 B = AES-256 key | `0xa4b0170` | mode 1 (AES-256, 16-byte blocks) — **the gate** |

The dispatcher at `0x7b38268` reads `ctx->+0x30` and picks mode 0 or 1.

## 2. The gate wire format

```
POST /pes22/gate/gate_CMD_*.php
Host: pes22-game.cs.konami.net
pes-custom-encrypt: AES256
Content-Type: application/x-www-form-urlencoded

body = IV(16 random bytes) ‖ AES-256-CBC(Key B, PKCS#7/16) of payload
```

* Requests carry a **zlib**-compressed payload.
* Responses carry a **gzip**-compressed payload.
* The compressed payload is **msgpack**.

Decrypting a captured body:

```python
from Crypto.Cipher import AES
import zlib, gzip, msgpack

KEY_B = bytes.fromhex("43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")

def open_gate(body):
    iv, ct = body[:16], body[16:]
    pt = AES.new(KEY_B, AES.MODE_CBC, iv).decrypt(ct)
    pt = pt[:-pt[-1]]                      # PKCS#7
    blob = (gzip.decompress(pt) if pt[:1] == b"\x1f"
            else zlib.decompress(pt))
    return msgpack.unpackb(blob, raw=False, strict_map_key=False)
```

A decoded request, verbatim:

```
msgid = CMD_GET_SERVER_ENV
rqid  = …
my_platform = ANDROID
lang = US, region = REGION_US
client_version = 6.0.1
```

## 3. The `sign` cookie (40 bytes, base64 → 56 chars)

```
key  = b"Xrq-RtAF_91MAE82" + b"|" + str((rand ^ clock) & 0xFFFFFFFF)
mac  = HMAC-SHA256(key, body)          # body = the encrypted bytes above
sign = base64(mac + clock_u32_le + rand_u32_le)
```

`clock` sits at bytes 32–36, `rand` at 36–40. `clock` is
`clock_gettime(CLOCK_BOOTTIME)` in nanoseconds and wraps every ~4.295 s.
Verified against 13/13 captured signatures.

## 4. The three traps that cost the most time

1. **The function-pointer tables are unreadable by default.** `libUE4.so`
   stores its relocations in Android's packed `APS2` format
   (`DT_ANDROID_RELA`), so every naive read of a vtable returns zeros.
   Decoding that stream (1,319,752 entries, consumed exactly) is what made
   the whole call chain resolvable. See `unpack_aps2.py` / `aps2.txt`.

2. **Mode 0 is a decoy for this traffic.** It is genuine, stock Blowfish-CBC
   with Key A — proven by transliterating the ARM64 core and matching a
   library byte-for-byte (`bf_exact.py`). It simply is not what the gate
   uses.

3. **Parse-only oracles hide correct answers.** Earlier sweeps only counted a
   hit if the plaintext parsed as gzip/msgpack/ASCII, which silently discards
   binary plaintext. The working oracle is PKCS#7 validity across all 42
   bodies, followed by a demand that the plaintext decompress *exactly*, with
   zero bytes left over (`aes_pkcs7.py` → `aes_gate.py`).

**The clue that picked AES over Blowfish:** all 42 bodies are multiples of 16.
With an 8-byte IV and 8-byte blocks that would force an odd plaintext block
count 42 times in a row (p ≈ 2⁻⁴²). Sixteen-byte alignment means a 16-byte
block cipher, and the only 16-byte-block candidate with a 32-byte key is
AES-256.

## 5. Directory layout

| path | contents |
|------|----------|
| `scripts/` | every analysis script (703 files) |
| `proofs/` | every disassembly dump and verdict file (714 files) |
| `corpus/flows.log` | the captured gate traffic the proofs run against |

Starting points, in the order they tell the story:

* `proofs/derived_keys.txt` + `scripts/derive_keys.py` — the key recipe
* `proofs/key_tables.txt` — generator disassembly
* `proofs/aps2.txt` + `scripts/unpack_aps2.py` — packed relocation decode
* `proofs/cipher_vtable.txt` — the cipher-object vtable
* `proofs/walk_core.txt` — Blowfish core, read instruction by instruction
* `proofs/bf_exact.txt` — proof that mode 0 is stock Blowfish
* `proofs/aes_gate.txt` — the decisive 42/42 decryption
* `proofs/peek_gate.txt` — raw bodies before any assumption
* `proofs/walk_post.txt` / `proofs/xref_post.txt` — the HTTP sender and the
  `a4`/`a5`/`a6` arguments
* `scripts/verify_sign_key.py` — the `sign` recipe, 13/13

## 6. Library identity

```
libUE4.so   160,822,968 bytes
sha256      2ac4ff17ac8ad713d9531c2601e38a3c8335e02ea882ba2dc4445c191c1298cd
```

## 7. Still open

* The `a4`/`a5`/`a6` arguments of the sub-request POST sender (`0x7d04148`).
  In the generic SOAP/UPnP sender (`0x7d03e10`) the same three slots are
  HTTP method, SOAP namespace and SOAP action; the gate's own caller has not
  been identified yet. `xref_post.txt` lists every call site.
* Mode 0's (Blowfish/Key A) actual purpose — no captured traffic uses it.
* `a4`/`a5`/`a6` were never cookies; the capture did not record HTTP headers,
  so no cookie material exists in `corpus/flows.log`.
