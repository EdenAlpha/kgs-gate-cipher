# Ghidra Jython script: find kill-rule strings, xrefs, decompile callers
# @category: Analysis
OUT = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\killrule_out2.txt"
targets = [
    "E_TURN_ALLOCATION_MISSMATCH",
    "MATCH_STOP_COUNT_SELF_BUF_EMPTY",
    "TurnReconnectWaitTimeMs",
    "NTL_PEER_KEEPALIVE_COUNT",
    "KeepAliveTimerUs",
    "reflexive_address",
    "CmdGetTurnServerList",
    "DETECT_NAT_ABORTED",
    "MatchAbortTimerCoefficient",
    "is_cheat_user",
    "OnlineModeTaskCheckCheat",
    "CHECK_STUN_RTT_TIMEOUT",
    "NTL_PEER_KEEPALIVE",
    "MultiplaySessionRecvThreadReceiveTimeoutUs",
]
lines = []
def log(s):
    lines.append(s)
    print(s)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
decomp = DecompInterface()
decomp.openProgram(currentProgram)
for t in targets:
    log("=" * 80)
    log("TARGET: " + t)
    hexpat = " ".join([ "%02x" % ord(c) for c in t ])
    found = []
    try:
        addrs = findBytes(currentProgram.getMinAddress(), hexpat, 5, ConsoleTaskMonitor())
        a = addrs
        while a is not None and len(found) < 5:
            found.append(a)
            try:
                a = findBytes(a.add(1), hexpat, 1, ConsoleTaskMonitor())
            except Exception:
                break
    except Exception as e:
        log("  find error: " + str(e))
        continue
    if not found:
        log("  no hits")
        continue
    for a in found:
        log("  string @ " + str(a))
        refs = getReferencesTo(a)
        n = 0
        for r in refs:
            if n >= 8:
                break
            fa = getFunctionContaining(r.getFromAddress())
            log("    xref from " + str(r.getFromAddress()) + " (" + r.getReferenceType().toString() + ") func=" + (str(fa) if fa else "None"))
            if fa is not None:
                try:
                    res = decomp.decompileFunction(fa, 60, ConsoleTaskMonitor())
                    if res and res.getDecompiledFunction():
                        code = res.getDecompiledFunction().getC()
                        for l in code.split("\n")[:120]:
                            log("      |" + l[:220])
                    else:
                        log("      (decompile failed: " + str(res.getErrorMessage() if res else "?") + ")")
                except Exception as e:
                    log("      (decompile exception: " + str(e) + ")")
            n += 1
        if n == 0:
            log("    (no xrefs)")
try:
    open(OUT, "w").write("\n".join(lines))
    print("WROTE " + OUT + " lines=" + str(len(lines)))
except Exception as e:
    print("WRITE FAIL " + str(e))
