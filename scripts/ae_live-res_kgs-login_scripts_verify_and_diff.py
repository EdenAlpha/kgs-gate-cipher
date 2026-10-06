#!/usr/bin/env python3
"""1) Prove the XAPK is the genuine Konami Play artifact (v2/v3 signature).
2) Diff the CURRENT 11.0.1 libUE4.so against the old build we had been
   reverse engineering -- endpoints, gRPC path, Def_ keys.

Point 2 matters most: every address/path/protocol value we have been
sending came from the OLD binary.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import struct
import zipfile

XAPK = os.path.expanduser(r"~\Downloads\apk\jp.konami.pesam.xapk")
OUT = os.path.expanduser(r"~\Downloads\apk")
NEW = os.path.join(OUT, "libUE4.so")
OLD = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
EXPECT_SIG = "d29e0251ecf7e15e06ad1874ee1c08213dfef3d4bce03032b181667f7389c4d2"
APK_SIG_MAGIC = b"APK Sig Block 42"
V2_ID = 0x7109871A
V3_ID = 0xF05368C0


def verify_v2(apk_bytes):
    """Parse the APK Signing Block, pull the v2/v3 signer cert, SHA-256 it."""
    # the magic sits immediately before the Central Directory
    i = apk_bytes.rfind(APK_SIG_MAGIC)
    if i < 0:
        return None, "no APK Signing Block"
    # block size field is the 8 bytes just before the magic
    blk_size = struct.unpack_from("<Q", apk_bytes, i - 8)[0]
    start = i - 8 - blk_size + 8
    blk = apk_bytes[start:i - 8]
    # ID-value pairs
    o = 0
    pairs = {}
    while o + 12 <= len(blk):
        plen, bid = struct.unpack_from("<QQ", blk, o)
        o += 12
        if plen == 0 or o + plen > len(blk):
            break
        pairs[bid] = blk[o:o + plen]
        o += plen + ((4 - (plen % 4)) % 4 if plen % 4 else 0)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    for bid, label in ((V3_ID, "v3"), (V2_ID, "v2")):
        if bid not in pairs:
            continue
        blob = pairs[bid]
        # signer sequence: len-prefixed; then signed data len, then signatures
        slen = struct.unpack_from(">I", blob, 0)[0]
        seq = blob[4:4 + slen]
        dsig_len = struct.unpack_from(">I", seq, 0)[0]
        p = 4 + dsig_len
        slen2 = struct.unpack_from(">I", seq, p)[0]
        p += 4
        signers = seq[p:p + slen2]
        o2 = 0
        while o2 + 8 <= len(signers):
            sl = struct.unpack_from(">I", signers, o2)[0]
            o2 += 4
            sdata = signers[o2:o2 + sl]
            o2 += sl
            if not sdata:
                continue
            dl = struct.unpack_from(">I", sdata, 0)[0]
            d = sdata[4:4 + dl]
            o3 = 4 + dl
            cl = struct.unpack_from(">I", d, o3)[0]
            o3 += 4
            cert = d[o3:o3 + cl]
            der = x509.load_der_x509_certificate(cert)
            fp = der.fingerprint(hashes.SHA256()).hex()
            print("  [%s] subject : %s" % (label, der.subject.rfc4514_string()))
            print("  [%s] SHA-256 : %s" % (label, fp))
            print("  [%s] == Konami Play cert: %s"
                  % (label, fp.lower() == EXPECT_SIG))
            return fp, label
    return None, "no v2/v3 signer found"


def strset(path):
    d = open(path, "rb").read()
    return set(m.decode("latin1") for m in re.findall(rb"[\x20-\x7e]{5,140}", d)), d


def main() -> int:
    z = zipfile.ZipFile(XAPK)
    mf = json.loads(z.read("manifest.json"))
    base = [e["file"] for e in mf["split_apks"] if e.get("id") == "base"][0]
    print("=== verifying %s (%s) ===" % (base, mf["version_name"]))
    fp, how = verify_v2(z.read(base))
    if fp is None:
        print("  ", how)

    if not (os.path.exists(NEW) and os.path.exists(OLD)):
        print("missing a binary")
        return 1

    print("\n=== libUE4.so: old vs new ===")
    for tag, p in (("OLD (analysed all day)", OLD), ("NEW 11.0.1 (phone)", NEW)):
        print("  %-28s %7.1f MB  sha256=%s"
              % (tag, os.path.getsize(p) / 1e6,
                 hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]))

    s_old, _ = strset(OLD)
    s_new, d_new = strset(NEW)

    def show(title, pred):
        o = sorted(x for x in s_old if pred(x))
        n = sorted(x for x in s_new if pred(x))
        print("\n--- %s ---" % title)
        print("  OLD: %s" % (", ".join(repr(x) for x in o[:6]) or "(none)"))
        print("  NEW: %s" % (", ".join(repr(x) for x in n[:6]) or "(none)"))
        if set(o) != set(n):
            print("  !! DIFFERENT between builds")

    show("Konami hosts",
         lambda x: re.search(r"[a-z0-9.-]*konami\.(net|com)", x) and len(x) < 60)
    show("gRPC service path",
         lambda x: re.match(r"^/[A-Za-z_]+\.[A-Za-z_]+/[A-Za-z_]+$", x))
    show("Def_Online_* keys", lambda x: x.startswith("Def_Online"))
    show("cmd_service / command_service",
         lambda x: "command_service" in x)
    show("gate_ URL template", lambda x: "gate_" in x and len(x) < 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
