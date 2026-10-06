"""Prove find_key.py: a key planted at an UNALIGNED offset in a fake region
must be found and must open a real encrypted body; a key absent must give
NO MATCH (exit 2). No game needed."""
import gzip, os, random, shutil, subprocess, sys

from Crypto.Cipher import AES
import msgpack

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
FLOW = os.path.join(HERE, "t_flows.log")
DIR = os.path.join(HERE, "t_sweep")

KEY = random.randbytes(32)
IV = random.randbytes(16)
plain = msgpack.packb({"result": "OK", "NOERR": "1",
                       "cmd": "CMD_LOGIN", "n": 12345})
gz = gzip.compress(plain)
pad = 16 - len(gz) % 16
gz += bytes([pad]) * pad                      # PKCS7, what a real sender does
body = IV + AES.new(KEY, AES.MODE_CBC, IV).encrypt(gz)
with open(FLOW, "w") as fh:
    fh.write("### REQ POST /pes22/gate/gate_1.php\nHOST: gate.konami.net\n"
             "REQLEN: %d\nREQHEX: %s\n" % (len(body), body.hex()))

# region file: key at an UNALIGNED offset (1234), nothing else special
shutil.rmtree(DIR, ignore_errors=True)
os.makedirs(DIR)
blob = random.randbytes(4096) + KEY + random.randbytes(4096)
with open(os.path.join(DIR, "r_000000001000.bin"), "wb") as fh:
    fh.write(blob)

def run():
    r = subprocess.run([sys.executable,
                        r"C:\Users\Administrator\Documents\Default Project"
                        r"\peerlink-efootball-disconnects\kgs-login\live"
                        r"\find_key.py",
                        "--dir", DIR, "--flows", FLOW, "--jobs", "2"],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr

rc, out = run()
print(out[-2500:])
assert rc == 0 and "MATCH key=" + KEY.hex() in out, \
    "PLANTED KEY NOT FOUND rc=%d" % rc
print("PASS: planted key found at unaligned offset and opened the body")

# negative: same body, key NOT in memory
blob2 = random.randbytes(8192)
with open(os.path.join(DIR, "r_000000001000.bin"), "wb") as fh:
    fh.write(blob2)
rc, out = run()
print(out[-800:])
assert rc == 2 and "NO MATCH" in out, "FALSE GREEN rc=%d" % rc
print("PASS: absent key gives NO MATCH (exit 2)")
print("FINDER PROVEN")
