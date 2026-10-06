import sqlite3, os, json, re, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
db = os.path.expandvars(r"%USERPROFILE%\.local\share\opencode\opencode.db")
c = sqlite3.connect("file:" + db.replace("\\", "/") + "?mode=ro", uri=True)
pat = re.compile(r"[A-Za-z0-9._%+-]+@gmail\.com")
hits = {}
for (data,) in c.execute("select data from session_message where data like '%@gmail.com%'"):
    for m in pat.findall(data):
        hits[m] = hits.get(m, 0) + 1
for k, v in sorted(hits.items(), key=lambda x: -x[1]):
    print("%-45s x%d" % (k, v))
print("distinct:", len(hits))
