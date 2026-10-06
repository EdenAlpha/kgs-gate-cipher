# Recovered key material

All values are read directly out of `libUE4.so` and reproduced by
`scripts/derive_keys.py`.

## Key B — the gate key (AES-256)

```
43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5
```

32 bytes, produced by loop B of the generator at VA `0x7d64fb0`, stored at
`.bss 0xa4b0170`, used by the mode-1 context `0xa4a98d0`.

## Key A — the mode-0 key (Blowfish)

```
a2df2319c1e5ec1e206a724b5709de77b728609eedbbfaaa939ab3d7bb4d7f77c135147cb76b4c2efa0249fad843a9d5cc38cae19cc41c90
```

56 bytes, loop A of the same generator, stored at `.bss 0xa4b0158`, used by the
mode-0 context `0xa4a98d8`.

## The recipe both come from

```
out[i] = src[i] ^ T1[i % 9] ^ T2[i % 12] ^ 0x75

T1 = 91969a94969a9398a0
T2 = 586c7e39282e392b292b2f19
```

* hidden source A: `.rodata 0x9823af8`, 56 bytes
* hidden source B: `.rodata 0x9823ba8`, 32 bytes
* the two XOR tables are byte-identical across both loops; only the source
  blob and the bound differ

## Blowfish tables (mode 0)

* P-array: `.rodata 0xc8d92c`, 72 bytes (18 words)
* S-boxes: `.rodata 0xc8d974`, 4096 bytes (4 x 256 words)
* standard constants: P[0] = 0x243f6a88, S0[0] = 0xd1310ba6

## `sign` cookie recipe

```
key  = b"Xrq-RtAF_91MAE82" + b"|" + str((rand ^ clock) & 0xFFFFFFFF)
mac  = HMAC-SHA256(key, body)
sign = base64(mac + clock_u32_le + rand_u32_le)
```

* `clock` = bytes 32–36 of the decoded cookie (u32 LE)
* `rand`  = bytes 36–40 (u32 LE)
* `clock` = `clock_gettime(CLOCK_BOOTTIME)` in ns; wraps every ~4.295 s
* verified 13/13 against captured signatures (`scripts/verify_sign_key.py`)

## Library identity

```
libUE4.so   160,822,968 bytes
sha256      2ac4ff17ac8ad713d9531c2601e38a3c8335e02ea882ba2dc4445c191c1298cd
```
