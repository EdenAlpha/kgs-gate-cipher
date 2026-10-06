import io, sys, math, collections
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from pathlib import Path
def ent(h):
    b = bytes.fromhex(h.strip())
    c = collections.Counter(b)
    n = len(b)
    e = -sum(v/n*math.log2(v/n) for v in c.values())
    return n, e, b[:16].hex()
base = Path(r'C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\kgs-login\captures')
for name in ['2026-10-01-login-conversation.log','2026-10-01-kgs-flows-requests.log']:
    t = (base/name).read_text(encoding='utf-8', errors='replace')
    print('==', name)
    for tag in ['REQHEX:','RESPHEX:']:
        import re
        for m in re.finditer(tag+r'\s*([0-9a-fA-F]+)', t):
            h = m.group(1)
            # find preceding path
            s = max(t.rfind('###', 0, m.start()-200), 0)
            line = t[s:m.start()].splitlines()
            path = next((l for l in reversed(line) if 'gate_' in l), '')[:90]
            n,e,head = ent(h)
            print(f'{tag[:3]} {path} len={n} ent={e:.2f} head={head}')
            if 'LOGIN' in path:
                break
        print()
