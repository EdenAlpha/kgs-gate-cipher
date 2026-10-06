#!/usr/bin/env python3
"""TLS fingerprint (JA3) hypothesis test.

Every client we have tried -- Python ssl, curl.exe, the phone's browser --
gets a byte-identical blank 500, while the app gets through.  If the server
rejects us at the TLS layer (JA3 fingerprinting), the response would change
with the TLS fingerprint even though the HTTP request is identical.

curl_cffi impersonates real browser TLS/HTTP2 fingerprints.  If any of them
gets past the blank 500, JA3 is the answer.
"""
from __future__ import annotations

from curl_cffi import requests

HOST = "https://pes22-game.cs.konami.net"
FORM = "application/x-www-form-urlencoded"
UA = "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"
BODY = open("real_body.bin", "rb").read()

IMPERSONATIONS = [
    "chrome99", "chrome101", "chrome110", "chrome120", "chrome124",
    "chrome131", "chrome133", "chrome136",
    "firefox109", "firefox133", "firefox135",
    "safari15_5", "safari17_0", "safari18_0", "safari26_0",
    "edge101", "opera117",
]


def label_of(resp) -> str:
    body = resp.content
    blank = body.strip() in (b"", b"0", b"0\r\n\r\n")
    if resp.status_code == 500 and blank:
        return "blank 500 (baseline)"
    return f"CHANGED: {resp.status_code} {body[:200]!r}"


print("=== TLS impersonation sweep ===", flush=True)
print(f"request: POST /pes22/gate/gate_CMD_LOGIN.php  {len(BODY)}B body\n",
      flush=True)

seen = {}
for imp in IMPERSONATIONS:
    try:
        r = requests.post(
            f"{HOST}/pes22/gate/gate_CMD_LOGIN.php",
            data=BODY,
            headers={"Content-Type": FORM, "User-Agent": UA,
                     "Accept": "*/*", "Connection": "close"},
            impersonate=imp,
            timeout=25,
            verify=False,
        )
        tag = label_of(r)
    except Exception as e:
        tag = f"ERR {type(e).__name__}: {e}"
    print(f"  {imp:14s} {tag}", flush=True)
    seen.setdefault(tag, []).append(imp)

print("\n=== summary ===", flush=True)
for tag, imps in seen.items():
    print(f"  {tag}", flush=True)
    print(f"      -> {', '.join(imps)}", flush=True)

# also: same fingerprint, different paths, to see whether ANYTHING responds
print("\n=== other paths under chrome136 ===", flush=True)
for path in ("/", "/pes22/", "/pes22/gate/", "/pes22/gate.php",
             "/pes22/gate/gate_CMD_BOGUS_DOES_NOT_EXIST.php",
             "/pes22/gate/gate_CMD_LOGIN.php"):
    try:
        r = requests.get(f"{HOST}{path}", impersonate="chrome136",
                         timeout=25, verify=False)
        print(f"  GET  {path:52s} {r.status_code}  {r.content[:100]!r}",
              flush=True)
    except Exception as e:
        print(f"  GET  {path:52s} ERR {type(e).__name__}", flush=True)
