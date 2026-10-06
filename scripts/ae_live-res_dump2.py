from reassemble import http_messages, decode, hms, safe

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
CLIFF1 = 1790386488724

msgs = http_messages(path)
print("reassembled messages: %d\n" % len(msgs))

best = None
for t, p, h, b in msgs:
    if p.endswith("ReportLog.php") and t <= CLIFF1 and (best is None or t > best[0]):
        best = (t, p, h, b)

t, p, h, b = best
print("Report at %s   ->  0pps_cliff at %s   (dt = %.2f s)"
      % (hms(t), hms(CLIFF1), (CLIFF1 - t) / 1000.0))
print("request headers:")
print("  " + safe(h.decode("ascii", "replace")).replace("\r\n", "\n  "))
print("\nbody: %d bytes" % len(b))
dat, txt = decode(b)
if dat:
    print("\n========== DECODED PAYLOAD (%d chars) ==========" % len(dat))
    print(safe(dat))
else:
    print(txt)
