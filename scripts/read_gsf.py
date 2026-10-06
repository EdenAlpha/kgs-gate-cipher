import sqlite3

DB = r"C:\Users\Administrator\AppData\Local\Temp\2\gsf2.db"
con = sqlite3.connect(DB)
cur = con.cursor()
for name in ("android_id", "device_id", "device_country", "user_country"):
    try:
        rows = cur.execute("select value from main where name = ?", (name,)).fetchall()
        for (value,) in rows:
            print("%-14s = %s  (len %d)" % (name, value, len(str(value))))
    except Exception as exc:
        print("%-14s : %s" % (name, exc))
