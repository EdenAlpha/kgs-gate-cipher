want = ["CmdGetVscomGameResult.php", "CmdAddScore.php", "CmdGetGameSessionCheckRes.php",
        "use_http_command", "connect_grpc_task", "CmdGetKgsGuestLoginToken.php",
        "CmdGetViewingUrl.php", "invitation_task"]
with open("ue4_strings.txt", encoding="utf-8", errors="replace") as f:
    for line in f:
        try:
            off, s = line.split("\t", 1)
        except ValueError:
            continue
        s = s.rstrip("\n")
        if s in want:
            print(off, repr(s))
