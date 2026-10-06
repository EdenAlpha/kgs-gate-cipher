import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = r'C:\Users\Administrator\AppData\Local\Temp\2\pmatch\passthrough_capture.csv'
BASE = 1790618919520

def hex_first(hx, n=24):
    try:
        b = bytes.fromhex(hx)
        return b[:n].hex(), len(b)
    except:
        return "", 0

targets = {
    ('34.140.40.38', '32617'),
    ('35.247.162.43', '5521'),
    ('166.117.130.199', '10000'),
    ('15.220.152.64', '30000'),
    ('51.34.16.129', '50000'),
}
from collections import defaultdict
samples = defaultdict(list)
times = {}
f = open(p, encoding='utf-8', errors='replace')
for line in f:
    if line.startswith('#'):
        continue
    a = line.strip().split(',', 8)
    if len(a) < 9:
        continue
    try:
        ts = int(a[0])
    except:
        continue
    dr, pr, dst, dp = a[1], a[2], a[5], a[6]
    if dr != 't':
        continue
    key = (dst, dp)
    if key in targets and len(samples[key]) < 3:
        hx = a[8]
        h, ln = hex_first(hx)
        samples[key].append(((ts - BASE) / 1000, h, ln))

for k, v in samples.items():
    print(f"== {k} ==")
    for t, h, ln in v:
        print(f"  +{t:.1f}s len={ln} head={h}")
        # STUN check: first 2 bytes 00 01, magic 21 12 a4 42 at offset 4
        if h.startswith('0001') and '2112a442' in h:
            print("    -> STUN Binding Request")
        if h.startswith('16fe') or h.startswith('17fe'):
            print("    -> DTLS?")
