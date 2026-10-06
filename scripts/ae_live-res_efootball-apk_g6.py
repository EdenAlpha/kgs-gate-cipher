import re
pats = {
 "BACKGROUND": r"(?i)background.{0,45}(timeout|disconnect|match|end|resume|pause)|is_background",
 "NETWORK_BLOCK": r"(?i)network.{0,30}block|blocked.{0,30}(net|conn)|firewall",
 "APP_LIFECYCLE": r"(?i)onpause|onresume|onstop|app.?state|lifecycle.{0,20}(match|disconnect)",
 "SYS_STATE": r"(?i)airplane|doze|standby|low.?memory|thermal.{0,20}(throttl|disconnect)|onlowmemory",
 "USER_QUIT": r"(?i)user.{0,15}(quit|abort|cancel)|quit_match|leave_match|exit_match",
 "P2P_PUNCH": r"(?i)punch.{0,30}(fail|timeout)|hole.?punch|nat.{0,25}(fail|timeout)",
 "TURN_RELAY": r"(?i)relay.{0,25}(fail|timeout|switch)|turn.{0,20}(fail|timeout)",
}
res={k:[] for k in pats}
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s=line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        for k,p in pats.items():
            if len(res[k])<40 and re.search(p,s):
                res[k].append((off,s))
for k in pats:
    print("="*6,k,"(%d)"%len(res[k]))
    for off,s in res[k]:
        print("   %s %r"%(off,s[:150]))
