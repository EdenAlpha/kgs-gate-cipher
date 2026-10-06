import sqlite3, os, json, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
db = os.path.expandvars(r"%USERPROFILE%\.local\share\opencode\opencode.db")
c = sqlite3.connect("file:" + db.replace("\\", "/") + "?mode=ro", uri=True)

rows = c.execute(
    "select session_id, type, seq, time_created, data from session_message "
    "where data like ? order by time_created",
    ("%millisec%",),
).fetchall()

def texts(o):
    if isinstance(o, dict):
        if isinstance(o.get("text"), str):
            yield o.get("role", ""), o["text"]
        for v in o.values():
            yield from texts(v)
    elif isinstance(o, list):
        for v in o:
            yield from texts(v)

seen = 0
for sid, typ, seq, ts, data in rows:
    try:
        j = json.loads(data)
    except Exception:
        continue
    for role, t in texts(j):
        low = t.lower()
        if "millisec" not in low:
            continue
        # skip giant tool outputs
        if len(t) > 6000:
            continue
        seen += 1
        print("=" * 90)
        print(f"session={sid} msgtype={typ} role={role} seq={seq} ts={ts}")
        # print the sentence around 'millisec'
        i = low.find("millisec")
        s = max(0, i - 700)
        print(t[s:i + 900])
print("printed:", seen)
