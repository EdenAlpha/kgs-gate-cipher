"""One command: report whether eFootball is installed, and start the copier.

The copier (sweep2.sh) loops until pidof returns a pid, so it can be started
now and will begin copying the instant the game launches -- i.e. exactly at
login, which is the only moment the key exists.
"""
import base64

src = open("sweep2.sh", "rb").read().replace(b"\r\n", b"\n")
b64 = base64.b64encode(src).decode()

body = (
    "exec echo CHECK+SWEEP; "
    "adb -s 127.0.0.1:5555 shell pm path jp.konami.pesam | tr -d '\\r' | head -3; "
    "echo " + b64 + " | base64 -d > /tmp/kgs/sweep2.sh && "
    "nohup bash /tmp/kgs/sweep2.sh >/tmp/kgs/sweep2.log 2>&1 & "
    "sleep 40; tail -3 /tmp/kgs/sweep2.log"
)
open("sweepcheck_cmd.txt", "wb").write(body.encode() + b"\n")
print("payload len:", len(body))