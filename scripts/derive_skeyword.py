#!/usr/bin/env python3
"""check_rel.py -- the per-build decoded constant XORed against the captured
s_keyword gives... what?"""

CONST_OLD = b"hGcKSg6k"          # old build, struct @0x9823c38
CONST_NEW = b"YE5PUd6m"          # new build, struct @0x9932ab0
SK        = b"^iSebQ\x18["       # captured s_keyword, client_version "6.0.1"

x = bytes(a ^ b for a, b in zip(CONST_OLD, SK))
print("const_old ^ s_keyword = %s" % x)
print("                      = %r" % x)
print()
print("captured client_version = '6.0.1'  (len %d)" % len("6.0.1"))
rep = ("6.0.1" * 4)[:8]
print("cv repeated, first 8    = %r" % rep)
print()
print("MATCH = %s" % (x == rep.encode()))
print()

# so: s_keyword[i] == CONST[i] ^ client_version[i % len(cv)]
print("hypothesis:  s_keyword[i] = CONST[i] ^ client_version[i %% len(cv)]")
print()

CV = "6.1.0"
for name, c in (("old-const", CONST_OLD), ("new-const", CONST_NEW)):
    out = bytes(c[i] ^ ord(CV[i % len(CV)]) for i in range(8))
    print("  cv=%s with %-9s -> %r" % (CV, name, out))
CV = "6.1.1"
for name, c in (("old-const", CONST_OLD), ("new-const", CONST_NEW)):
    out = bytes(c[i] ^ ord(CV[i % len(CV)]) for i in range(8))
    print("  cv=%s with %-9s -> %r" % (CV, name, out))
