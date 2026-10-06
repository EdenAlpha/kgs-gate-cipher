import sys
want = ["is_network_blocked_disconn","is_background_timeout","is_background_at_match",
        "user_network_status","is_stun_keep_alive_failed","intentional_give_up",
        "abnormalend_reason","is_problem","error_code","STRANGE_MATCH_END",
        "match_forfeited","is_join_game","NORMAL_GIVEUP","is_enable_giveup"]
found={}
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s=line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        if s in want and s not in found:
            found[s]=off
        if len(found)==len(want): break
for w in want:
    print("%-30s %s"%(w, found.get(w,"NOT FOUND")))
