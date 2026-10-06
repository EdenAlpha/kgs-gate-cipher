import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = r'C:\Users\Administrator\AppData\Local\Temp\2\pmatch\passthrough_capture.csv'
targets = {'34.111.40.119', '130.211.8.132', '44.255.253.52', '34.208.149.190'}
f = open(p, encoding='utf-8', errors='replace')
seen = {}
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
    if dst not in targets or dr != 't' or pr != 'tcp':
        continue
    if dst in seen:
        continue
    try:
        b = bytes.fromhex(a[8])
    except:
        continue
    txt = ''.join(chr(c) if 32 <= c < 127 else ' ' for c in b)
    cands = re.findall(r'(?:[a-z0-9-]+\.)+(?:net|com|jp|googleapis|google|konami|cloudfront|amazonaws|android|gstatic)[a-z0-9.-]*', txt)
    if cands:
        seen[dst] = cands[:3]
for k, v in seen.items():
    print(k, v)
