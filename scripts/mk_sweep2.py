"""Deploy sweep2.sh (minimal copier) as base64 and start it detached.

The v1 sweeper copies 0 bytes (PULL FAILED every region) while the manual
copy with the same dd shape returned 32 KB clean (result 1253). Rather than
debugging v1 remotely with 20 minutes on the loop clock, deploy this minimal
loop that uses only the proven shape, and verify bytes on the next probe.
"""
import base64
import subprocess

raw = open("sweep2.sh", "rb").read().replace(b"\r\n", b"\n")
assert b"\r" not in raw
b64 = base64.b64encode(raw).decode()
payload = ("exec pkill -f 'bash /tmp/kgs/sweep.sh'; sleep 2; echo %s | base64 -d > /tmp/kgs/sweep2.sh && "
           "nohup bash /tmp/kgs/sweep2.sh >/tmp/kgs/sweep2.log 2>&1 & sleep 50; tail -4 /tmp/kgs/sweep2.log"
           % b64).encode() + b"\n"
open("sweep2_cmd.txt", "wb").write(payload)
print("payload len:", len(payload))

r = subprocess.run(["python", "push_cmd.py", "sweep2_cmd.txt",
                    "lane k: deploy minimal copier v2 (proven dd shape) + start, show first cycles"],
                   capture_output=True, text=True)
print(r.stdout[-500:])
print(r.stderr[-200:])
