import sqlite3, os, json, re, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
db = os.path.expandvars(r"%USERPROFILE%\.local\share\opencode\opencode.db")
c = sqlite3.connect("file:" + db.replace("\\", "/") + "?mode=ro", uri=True)

rows = c.execute(
    "select session_id, type, seq, data from session_message "
    "where data like ? order by time_created", ("%efootballudp%",)).fetchall()
print("messages mentioning efootballudp:", len(rows))


def texts(o):
    if isinstance(o, dict):
        if isinstance(o.get("text"), str):
            yield o["text"]
        for v in o.values():
            yield from texts(v)
    elif isinstance(o, list):
        for v in o:
            yield from texts(v)


pat = re.compile(r"efootballudp", re.I)
for sid, typ, seq, data in rows:
    try:
        j = json.loads(data)
    except Exception:
        continue
    for t in texts(j):
        if not pat.search(t):
            continue
        if len(t) > 4000:
            continue          # tool output, not a chat line
        i = pat.search(t).start()
        s = max(0, i - 500)
        print("=" * 90)
        print("session=%s type=%s seq=%s" % (sid, typ, seq))
        print(t[s:i + 700])
