import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = r'C:\Users\Administrator\AppData\Local\Temp\2\pmatch\passthrough_capture.csv'
BASE = 1790618919520

def udp_payload(hx):
    try:
        b = bytes.fromhex(hx)
    except:
        return None
    if len(b) < 28 or b[0] >> 4 != 4:
        return None
    ihl = (b[0] & 0x0F) * 4
    if len(b) < ihl + 8:
        return None
    return b[ihl+8:]

from collections import defaultdict
counts = defaultdict(int)
first = {}
last = {}
samples = {}
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
    if pr != 'udp' or dr != 't':
        continue
    if dst.startswith('10.') or dst.startswith('192.168.'):
        continue
    key = (dst, dp)
    counts[key] += 1
    if key not in first:
        first[key] = ts
    last[key] = ts
    if key not in samples:
        pl = udp_payload(a[8])
        if pl is not None:
            samples[key] = pl[:32].hex()

# focus: 5521 / 10000 / 30000 / 50000 / 32617
for (dst, dp) in sorted(first, key=lambda k: first[k]):
    if dp not in ('5521', '10000', '30000', '50000', '32617'):
        continue
    t0 = (first[(dst, dp)] - BASE) / 1000
    t1 = (last[(dst, dp)] - BASE) / 1000
    h = samples.get((dst, dp), '')
    kind = ''
    if h.startswith('0001') and '2112a442' in h:
        kind = 'STUN-binding-req'
    elif h.startswith('0101'):
        kind = 'STUN-binding-resp?'
    print(f"+{t0:6.1f}s->{t1:6.1f}s {dst}:{dp} n={counts[(dst,dp)]} head={h[:48]} {kind}")
    if counts[(dst, dp)] > 100:
        break
print('--- distinct 5521 dsts:', sum(1 for k in first if k[1] == '5521'))
