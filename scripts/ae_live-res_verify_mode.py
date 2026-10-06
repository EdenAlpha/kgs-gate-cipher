"""verify_mode.py -- does Konami's bundled OpenSSL actually verify the server
cert, and can we get the keys?

libUE4.so ships OpenSSL + libcurl (proved by native_pin_scan.py).  The three
things that decide whether MITM works:

  1. is a verify callback installed?      (SSL_CTX_set_cert_verify_callback)
  2. what verify mode is set?             (SSL_VERIFY_PEER vs SSL_VERIFY_NONE)
  3. is SSLKEYLOGFILE honoured?           (OpenSSL's standard key-dump hook)
"""

import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))
STRDUMP = os.path.join(BASE, "efootball-apk", "ue4_strings.txt")

with open(STRDUMP, "r", encoding="utf-8", errors="replace") as fh:
    blob = fh.read()


def show(title, needles, ctx=110):
    print("=" * 78)
    print(title)
    print("=" * 78)
    hit = False
    for needle in needles:
        n = blob.count(needle)
        if n:
            hit = True
            i = blob.find(needle)
            c = blob[max(0, i - ctx):i + len(needle) + ctx]
            print("  HIT  %-46s x%d" % (needle, n))
            print("        ...%s..." % re.sub(r"\s+", " ", c).strip())
        else:
            print("  --   %-46s 0" % needle)
    if not hit:
        print("  (no hits)")
    print()


show("1. custom verify callback / verifier override", [
    "SSL_CTX_set_cert_verify_callback",
    "SSL_set_cert_verify_callback",
    "SSL_CTX_set_verify",
    "SSL_set_verify",
    "SSL_CTX_set_verify_depth",
    "SSL_CTX_load_verify_locations",
    "SSL_CTX_set_default_verify_paths",
    "SSL_CTX_get_verify_callback",
    "X509_STORE_set_verify_cb",
    "SSL_VERIFY_PEER",
    "SSL_VERIFY_NONE",
    "SSL_VERIFY_FAIL_IF_NO_PEER_CERT",
])

show("2. curl's pinning option", [
    "CURLOPT_PINNEDPUBLICKEY",
    "CURLOPT_CAINFO",
    "CURLOPT_CAPATH",
    "CURLOPT_SSL_VERIFYPEER",
    "CURLOPT_SSL_VERIFYHOST",
    "CURLSSLOPT_NO_REVOKE",
    "CURLOPT_PROXY_SSL_VERIFYPEER",
])

show("3. key logging (SSLKEYLOGFILE) + config hooks", [
    "SSLKEYLOGFILE",
    "SSL_CTX_set_keylog_callback",
    "SSL_CTX_set_session_cache_mode",
    "SSL_CONF_cmd",
    "OPENSSL_CONF",
    "SSL_CTX_ctrl",
    "EVP_sha256",
])

show("4. Konami-specific / app-side TLS strings", [
    "info.service.konami.net",
    "ntl.service.konami.net",
    "pes22-game.cs.konami.net",
    "konami.net",
    "SetCertVerify",
    "setCertificateVerifier",
    "TrustManager",
    "checkServerTrusted",
])

# Where does SSLKEYLOGFILE appear?  next to a getenv?
print("=" * 78)
print("5. every SSLKEYLOGFILE occurrence with context")
print("=" * 78)
for m in re.finditer(r"SSLKEYLOGFILE", blob):
    i = m.start()
    print("   ...%s..." % re.sub(r"\s+", " ", blob[max(0, i - 160):i + 160]).strip())
    print()

# hostname verification
print("=" * 78)
print("6. hostname verification entry points")
print("=" * 78)
for n in ["SSL_set1_host", "SSL_set_hostflags", "X509_VERIFY_PARAM_set1_host",
          "X509_VERIFY_PARAM_set_hostflags", "SSL_check_host",
          "X509_check_host", "X509_check_ip", "X509_check_ip_asc",
          "CURLOPT_SSL_VERIFYHOST", "SSL_VERIFYHOST"]:
    print("  %-42s %s" % (n, blob.count(n)))
