import zipfile, os

BASE = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk"
SO = os.path.join(BASE, "native", "lib", "arm64-v8a", "libUE4.so")

print("### 1) JNI crypto strings inside libUE4.so ###")
data = open(SO, "rb").read()
so_pats = [
    b"javax/crypto/Cipher", b"javax.crypto.Cipher",
    b"AES/CBC/PKCS5Padding", b"AES/CTR/NoPadding", b"AES/GCM/NoPadding",
    b"AES/ECB/PKCS5Padding", b"AES/CBC/NoPadding", b"AES/CTR/PKCS5Padding",
    b"javax/crypto/spec/SecretKeySpec", b"javax/crypto/spec/IvParameterSpec",
    b"java/security/MessageDigest", b"android/util/Base64",
    b"javax/crypto/SecretKeyFactory", b"PBKDF2WithHmacSHA1", b"PBKDF2WithHmacSHA256",
    b"addRequestHeader", b"setRequestHeader", b"AES",
]
for p in so_pats:
    hits = []
    k = data.find(p)
    while k >= 0 and len(hits) < 4:
        hits.append(k)
        k = data.find(p, k + 1)
    if hits:
        print("   HIT %-42r %s" % (p, ["0x%x" % h for h in hits]))
        print("        ctx %r" % data[hits[0]:hits[0] + 96])
    else:
        print("   --  %r" % p)
del data
print()

print("### 2) dex / assets carrying the literals ###")
apks = ["jp.konami.pesam.apk", "pad_it_0.apk", "pad_it_1.apk", "config.arm64_v8a.apk"]
pats = [b"pes-custom-encrypt", b"custom-encrypt", b"AES256", b"gate_CMD_",
        b"/pes22/gate/", b"AddRequestHeader", b"GetKgsGuestLoginToken", b"pes22"]
for a in apks:
    path = os.path.join(BASE, a)
    if not os.path.exists(path):
        print("  missing", a)
        continue
    z = zipfile.ZipFile(path)
    names = z.namelist()
    dex = [n for n in names if n.endswith(".dex")]
    print("== %s: %d entries, dex=%s" % (a, len(names), dex))
    for n in names:
        try:
            info = z.getinfo(n)
            if info.file_size > 400 * 1048576:
                continue
            b = z.read(n)
        except Exception as e:
            print("   skip %s (%s)" % (n, e))
            continue
        for p in pats:
            k = b.find(p)
            if k >= 0:
                print("   HIT %-44s %-24r at %d" % (n, p, k))
                print("        ctx %r" % b[max(0, k - 48):k + 96])
    z.close()
print()
print("DONE")
