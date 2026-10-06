import os, re, collections
root = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\jadx_out\sources"
pats = {
 "CertificatePinner": re.compile(r"CertificatePinner"),
 "TrustManager":      re.compile(r"X509TrustManager|TrustManagerFactory|checkServerTrusted"),
 "HostnameVerifier":  re.compile(r"HostnameVerifier|ALLOW_ALL_HOSTNAME|DefaultHostnameVerifier"),
 "OkHttp pin":        re.compile(r"\.pin\(|certificatePinner"),
 "WebViewClient cert":re.compile(r"onReceivedSslError"),
 "sslcontext":         re.compile(r"SSLContext|SSL\.getInstance"),
 "https base url":     re.compile(r"https://[a-z0-9.\-]*konami"),
 "cleartextTraffic":   re.compile(r"usesCleartextTraffic|network_security_config"),
}
hits = collections.defaultdict(list)
files = 0
for dp, dn, fn in os.walk(root):
    for f in fn:
        if not f.endswith(".java"): continue
        p = os.path.join(dp, f)
        try:
            t = open(p, encoding="utf-8", errors="replace").read()
        except Exception: continue
        files += 1
        rel = os.path.relpath(p, root)
        for k, rx in pats.items():
            if rx.search(t) and len(hits[k]) < 12:
                hits[k].append(rel)
print("java files scanned:", files)
for k in pats:
    print("\n=== %s  (%d shown)" % (k, len(hits[k])))
    for h in hits[k]: print("   ", h)
