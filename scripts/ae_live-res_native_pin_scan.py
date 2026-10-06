"""native_pin_scan.py -- the gap in the earlier "no cert pinning" claim.

pin_scan.py only covered jadx Java sources.  eFootball ships exactly one
native library (libUE4.so, 153 MB) and there is no networkSecurityConfig and
no usesCleartextTraffic in the manifest, so any TLS implementation -- and any
pinning -- would have to be inside libUE4.so.

Scans both the extracted string dump and the raw library bytes.
"""

import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
STRDUMP = os.path.join(BASE, "efootball-apk", "ue4_strings.txt")
SO = os.path.join(BASE, "efootball-apk", "native", "lib", "arm64-v8a",
                  "libUE4.so")

# ordered: pinning-specific first, generic-TLS second, then unrelated hits
PIN_SPECIFIC = [
    "SSL_CTX_set_cert_verify_callback",
    "SSL_CTX_set_verify",
    "SSL_set_cert_verify_callback",
    "SSL_set1_host",
    "X509_VERIFY_PARAM_set1_host",
    "SSL_check_host",
    "X509_check_host",
    "X509_verify_cert",
    "SSL_get_verify_result",
    "CertificatePinner",
    "checkServerTrusted",
    "pubkey_pin",
    "spki_pin",
    "certificate_pin",
    "cert_pin",
    "ssl_pin",
    "hpkp",
    "EXPECT_PUBLIC_KEY",
    "X509_digest",
    "i2d_X509",
]

TLS_GENERIC = [
    "BoringSSL", "boringssl", "OpenSSL", "openssl",
    "SSL_CTX_new", "SSL_new", "SSL_connect", "SSL_do_handshake",
    "SSL_read", "SSL_write", "TLSv1", "SSLv23",
    "X509_STORE_CTX", "X509_new", "PEM_read",
    "EVP_sha256", "EVP_Digest",
    "SSL_CIPHER", "CLIENT_HELLO", "SERVER_HELLO",
]

PIN_WORDS = ["pinning", "pinned", "pin_cert", "publicKeyHash",
             "PublicKeyHash", "sha256/"]

print("=" * 78)
print("targets")
print("=" * 78)
print("  string dump : %s" % STRDUMP)
print("               %s" %
      ("present, %d bytes" % os.path.getsize(STRDUMP)
       if os.path.exists(STRDUMP) else "MISSING"))
print("  library     : %s" % SO)
print("               %s" %
      ("present, %d bytes" % os.path.getsize(SO)
       if os.path.exists(SO) else "MISSING"))
print()

if os.path.exists(STRDUMP):
    with open(STRDUMP, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    joined = "".join(lines)

    print("=" * 78)
    print("A. exact pinning API names in libUE4.so's string dump")
    print("=" * 78)
    any_pin = False
    for needle in PIN_SPECIFIC:
        n = joined.count(needle)
        if n:
            any_pin = True
            idx = joined.find(needle)
            ctx = joined[max(0, idx - 90):idx + len(needle) + 90]
            print("  HIT  %-38s x%d" % (needle, n))
            print("        ...%s..." % re.sub(r"\s+", " ", ctx).strip())
    if not any_pin:
        print("  ZERO hits for all %d pinning-specific API names." %
              len(PIN_SPECIFIC))

    print()
    print("=" * 78)
    print("B. generic TLS presence (is there even a TLS stack in here?)")
    print("=" * 78)
    for needle in TLS_GENERIC:
        n = joined.count(needle)
        if n:
            print("  HIT  %-38s x%d" % (needle, n))
    # anything TLS-ish at all
    loose = sorted(set(re.findall(
        r"[A-Za-z0-9_]*(?:SSL|TLS|X509|x509)[A-Za-z0-9_]*", joined)))
    print("\n  distinct SSL/TLS/X509-ish identifiers: %d" % len(loose))
    for s in loose[:60]:
        print("     ", s)

    print()
    print("=" * 78)
    print("C. pin-ish words")
    print("=" * 78)
    for needle in PIN_WORDS:
        n = joined.count(needle)
        print("  %-34s %s" % (needle, ("x%d" % n) if n else "0"))

    print()
    print("=" * 78)
    print("D. https:// URLs in the library")
    print("=" * 78)
    urls = sorted(set(re.findall(r"https://[!-~]{4,120}", joined)))
    print("  count: %d" % len(urls))
    for u in urls[:40]:
        print("     ", u)

if os.path.exists(SO):
    print()
    print("=" * 78)
    print("E. raw-byte scan of the library (catches strings the dump filtered)")
    print("=" * 78)
    with open(SO, "rb") as fh:
        blob = fh.read()
    for needle in PIN_SPECIFIC + ["CertificatePinner", "checkServerTrusted"]:
        n = blob.count(needle.encode())
        if n:
            print("  HIT  %-38s x%d" % (needle, n))
    print("  (silence above = zero hits in raw bytes too)")
