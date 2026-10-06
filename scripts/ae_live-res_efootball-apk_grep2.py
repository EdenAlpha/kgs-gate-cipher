import re
pats = [
 ("TIMEOUT_SEC_KEYS", r"[a-z_]*timeout_sec|[a-z_]*_timeout_msec|_msec$"),
 ("NETFAIL", r"ENetworkFailure|NetworkFailure::"),
 ("ABNORMAL_END", r"(?i)abnormal_?end|abnormalend|abnormal_termination"),
 ("OTHERUSER", r"Other user|other_user|otheruser"),
 ("MATCH_END", r"(?i)match_?(end|result|finish)|MatchEnd|EndReason|end_reason|ResultReason"),
 ("P2P_ADHOC", r"P2P_ADHOC|ADHOC_"),
 ("CAUSE", r"(?i)_cause$|CauseCode|reason_code|Cause::"),
 ("SESSION", r"match_session|MatchSession"),
 ("KEEPALIVE", r"(?i)keepalive|keep_alive"),
]
res={k:[] for k,_ in pats}
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s = line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        for (k,p) in pats:
            if len(res[k])<150 and re.search(p,s):
                res[k].append((off,s))
for k,_ in pats:
    print("="*8,k,"(",len(res[k]),")")
    for off,s in res[k]:
        print("  ",off,s[:400])
