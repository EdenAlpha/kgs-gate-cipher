import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = r'C:\Users\Administrator\AppData\Local\Temp\2\pmatch\passthrough_capture.csv'
BASE = 1790618919520
f = open(p, encoding='utf-8', errors='replace')
n = 0
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
    if dst == '52.196.4.126' and dp == '80' and dr == 't':
        hx = a[8]
        try:
            b = bytes.fromhex(hx)
        except:
            continue
        txt = b.decode('utf-8', errors='replace')
        idx1 = txt.find('GET ')
        idx2 = txt.find('POST ')
        idx = idx1 if idx1 >= 0 else idx2
        if idx >= 0:
            rel = (ts - BASE) / 1000
            print(f"ts+{rel:.1f}s {txt[idx:idx+380]!r}")
            n += 1
            if n > 8:
                break
