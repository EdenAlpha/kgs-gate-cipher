import re
pats = {
 "ABNORMAL": r"Abnormal|abnormal",
 "DISCONNECT_WORD": r"(?i)\bdisconnect",
 "OPPONENT": r"(?i)opponent.{0,40}(left|quit|disconnect|lost|end|terminat)|left the match|left the game",
 "TIMEOUT_MSG": r"(?i)(connection|connect|network|peer|match).{0,30}timeout|timeout.{0,30}(connection|match)",
 "WATCHDOG": r"(?i)watchdog|watch_dog",
 "NTL_ERR": r"NTL_|E_NTL|NtlErr|ntl_error",
 "FORFEIT": r"(?i)forfeit|walkover|abandon|resign",
 "GIVEUP": r"(?i)give.?up|giveup",
 "RECONNECT": r"(?i)reconnect",
}
res={k:[] for k in pats}
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try:
            off,s = line.split("\t",1)
        except ValueError:
            continue
        s=s.rstrip("\n")
        for k,p in pats.items():
            if re.search(p,s):
                if len(res[k])<200:
                    res[k].append((off,s))
for k in pats:
    print("="*10, k, "(", len(res[k]), "shown )")
    for off,s in res[k][:60]:
        print("  ",off,s[:190])
