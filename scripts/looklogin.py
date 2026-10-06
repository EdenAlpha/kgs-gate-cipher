import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from pathlib import Path
p = Path(r'C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\kgs-login\captures\2026-10-01-login-conversation.log')
t = p.read_text(encoding='utf-8', errors='replace')
i = t.find('gate_CMD_LOGIN')
print(t[max(0,i-800):i+3000][:3500])
