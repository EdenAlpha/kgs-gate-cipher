import base64, os, sys

RELAY = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\kgs-login\live\relay.py"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\relay_restart_cmd.txt"

raw = open(RELAY, "rb").read().replace(b"\r\n", b"\n")
b64 = base64.b64encode(raw).decode()

# Keep the EXISTING token (/tmp/rt) and the EXISTING tunnel: only the code is
# swapped, so the URL and token we already hold keep working.
TPL = ("exec bash -c true; echo RELAYUP2; "
       "pkill -f 'python3 /tmp/relay.py'; sleep 1; "
       "echo %B64% | base64 -d > /tmp/relay.py; "
       "export RELAY_TOKEN=$(cat /tmp/rt); "
       "nohup python3 /tmp/relay.py >/tmp/relay.log 2>&1 & sleep 2; "
       "echo PROCS; pgrep -af relay.py | head -3; "
       "echo LOGTAIL; tail -3 /tmp/relay.log")
cmd = TPL.replace("%B64%", b64)

assert "\r" not in cmd and "\n" not in cmd
with open(OUT, "wb") as fh:
    fh.write(cmd.encode() + b"\n")

embedded = cmd.split("echo RELAYUP2; pkill -f 'python3 /tmp/relay.py'; sleep 1; echo ",
                     1)[1].split(" | base64 -d", 1)[0]
assert base64.b64decode(embedded) == raw, "ROUND TRIP MISMATCH"
print("command bytes:", len(cmd), " relay bytes:", len(raw), " round trip: OK")
