import os,re
paths=[
 "peerlink-efootball-disconnects/kgs-login/scripts",
 "peerlink-efootball-disconnects/kgs-login",
 "peerlink-efootball-disconnects/kgs-login/live",
]
for root,_,files in os.walk("peerlink-efootball-disconnects/kgs-login"):
    for f in files:
        if f.endswith(('.py','.sh','.md','.js','.kt')):
            p=os.path.join(root,f)
            try: t=open(p,encoding='utf-8',errors='ignore').read()
            except: continue
            for i,l in enumerate(t.splitlines(),1):
                if ('REQHEX' in l or 'gate_body' in l or 'bodyb64' in l.lower() or 'gzip.decompress' in l) and ('b64' in l or 'base64' in l or 'decompress' in l or 'import' in f):
                    if i>3 and 'import' in l.lower() or 'b64' in l:
                        print(p, i, l[:140])
                    break
