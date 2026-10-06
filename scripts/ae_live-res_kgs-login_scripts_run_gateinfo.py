"""Live step 1 of the handshake: run the game's own GateInfo request against
Konami and print every line the server sends back.  Then sweep the LIVE
script directory with the game's own endpoint names."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from peerlink import kgs  # noqa: E402

print("=" * 70)
print("LIVE: NTL GateInfo  (the game's bootstrap request)")
print("=" * 70)

variants = [
    ("pes22", "en", "dt270"),
    ("XWW020-E1", "en", "dt270"),
    ("pes22", "en", ""),
    ("pes22", "ja", "dt270"),
]
for tc, loc, ver in variants:
    url = kgs.DEFAULT_GATEINFO_URL
    print(f"\n--- titleCode={tc!r} locale={loc!r} version={ver!r}")
    print(f"    POST {url}")
    try:
        out = kgs.gate_info(title_code=tc, locale=loc, version=ver)
        for k, v in out.items():
            print(f"      {k} = {v}")
    except Exception as e:
        print(f"      ERROR {type(e).__name__}: {e}")

# raw body, unbent, for the primary variant
print("\n" + "=" * 70)
print("RAW response body (primary variant)")
print("=" * 70)
import json
import urllib.request  # noqa: E402
payload = {"titleCode": "pes22", "locale": "en", "version": "dt270",
           "extra": "", "apiLevel": 1}
body = "req=" + json.dumps(payload, separators=(",", ":")).encode().hex()
req = urllib.request.Request(
    kgs.DEFAULT_GATEINFO_URL, data=body.encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded",
             "User-Agent": "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"},
    method="POST")
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
    print(f"HTTP {r.status}")
    print(raw.decode("utf-8", "replace"))
except Exception as e:
    print(f"ERROR {type(e).__name__}: {e}")

# ---- sweep the live NTL directory with the game's own endpoint names ----
print("=" * 70)
print("SWEEP: game's own Cmd*.php names on the LIVE Apache host")
print("=" * 70)
import socket  # noqa: E402
import ssl  # noqa: E402

HOST = "ntl.service.konami.net"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def head(path):
    try:
        s = socket.create_connection((HOST, 443), timeout=10)
        ss = ctx.wrap_socket(s, server_hostname=HOST)
        ss.sendall(f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
                   f"User-Agent: PES/1.0\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            ch = ss.recv(65536)
            if not ch:
                break
            data += ch
            if len(data) > 40000:
                break
        ss.close()
        line = data.split(b"\r\n")[0].decode("utf-8", "replace")
        bdy = data.partition(b"\r\n\r\n")[2]
        return line, bdy
    except Exception as e:
        return f"ERR {e}", b""


bases = ["/ntl/api/", "/ntl/api/PES2022/", "/ntl/api/pes22/",
         "/ntl/api/pes2022/"]
found = []
for b in bases:
    for key, name in kgs.CMD.items():
        code, bdy = head(b + name)
        code = code.split(" ")[1] if " " in code else code
        if code == "200":
            found.append(b + name)
            print(f"  200  {b + name}   body={bdy[:160]!r}")
    # directory existence check on this base
    code, bdy = head(b + "index.html")
    print(f"  {code:5}  {b}index.html")

print(f"\n200 hits: {len(found)}")
for f in found:
    print("   ", f)
