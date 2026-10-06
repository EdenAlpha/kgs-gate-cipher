#!/usr/bin/env python3
"""Copy the whole PeerLink / KGS-login investigation into the repo.

Layout produced:
    kgs-login/README.md      index, beginning -> end
    kgs-login/findings/      the M-series notes + verdicts
    kgs-login/scripts/       every tool written along the way
    kgs-login/harness/       the Unicorn emulator harness (uc_loader + peerlink)
    kgs-login/evidence/      outputs that prove the claims

Deliberately NOT copied (regenerable or not ours to redistribute):
    pristine_libUE4.so, funcs_eh.txt, ghidra_vtables.txt, dynsym_funcs.txt
    apk_lab/ (packed_relocs.npz ~374 MB, plt_map.json)
    ghidra_proj/, __pycache__/, *.html scrape dumps, *.apk stubs
    *_key.pem / bin_privkey.pem  <- Konami's client TLS private key
"""
from __future__ import annotations

import os
import shutil

SRC = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
DST = (r"C:\Users\Administrator\Documents\Default Project"
       r"\peerlink-efootball-disconnects\kgs-login")

SKIP_SUBSTR = ("__pycache__", "pristine_libUE4", "funcs_eh.txt",
               "ghidra_vtables.txt", "dynsym_funcs.txt")
SKIP_EXT = (".html", ".apk", ".apks", ".so", ".npz")
SKIP_NAMES = {"bin_privkey.pem", "client_key.pem", "chain_key.pem",
              "ChangeServer.bin", "serve_test.py"}
MAX_EVIDENCE = 600_000          # keep evidence files under 600 KB

FINDINGS = ("FINDINGS_M22_live_login.md", "FINDINGS_M23_dispatch_tables.md",
            "FINDINGS_M24_http_stack.md", "FINDINGS_M25_gate_endpoint.md",
            "FINDINGS_M26_vtables_zero.md")

copied = {"findings": 0, "scripts": 0, "harness": 0, "evidence": 0}
bytes_total = 0


def put(rel: str, src: str) -> None:
    global bytes_total
    dst = os.path.join(DST, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    sz = os.path.getsize(dst)
    bytes_total += sz
    top = rel.split("/")[0]
    copied[top] = copied.get(top, 0) + 1


def want(name: str) -> bool:
    if name in SKIP_NAMES:
        return False
    if any(s in name for s in SKIP_SUBSTR):
        return False
    if name.endswith(SKIP_EXT):
        return False
    return True


def main() -> int:
    os.makedirs(DST, exist_ok=True)

    # 1. findings notes
    for f in FINDINGS:
        p = os.path.join(SRC, f)
        if os.path.isfile(p):
            put(f"findings/{f}", p)

    # 2. every tool written along the way (top-level .py)
    for f in sorted(os.listdir(SRC)):
        p = os.path.join(SRC, f)
        if os.path.isfile(p) and f.endswith(".py") and want(f):
            put(f"scripts/{f}", p)

    # 3. the emulator harness
    for sub in ("scripts", "peerlink"):
        root = os.path.join(SRC, sub)
        for dirpath, _dirs, files in os.walk(root):
            if "__pycache__" in dirpath:
                continue
            for f in sorted(files):
                if not want(f):
                    continue
                p = os.path.join(dirpath, f)
                rel = os.path.relpath(p, SRC).replace(os.sep, "/")
                put(f"harness/{rel}", p)

    # 4. evidence: bodies, logs, key outputs, the Ghidra script
    gs = os.path.join(SRC, "ghidra_scripts")
    if os.path.isdir(gs):
        for f in sorted(os.listdir(gs)):
            if f.endswith(".java"):
                put(f"evidence/ghidra/{f}", os.path.join(gs, f))

    for f in sorted(os.listdir(SRC)):
        p = os.path.join(SRC, f)
        if not os.path.isfile(p) or not want(f):
            continue
        if f.endswith(".py"):
            continue                      # already in scripts/
        if f.endswith((".txt", ".log", ".bin", ".json", ".pem")):
            if os.path.getsize(p) <= MAX_EVIDENCE:
                put(f"evidence/{f}", p)

    print(f"copied {sum(copied.values())} files, {bytes_total/1e6:.2f} MB")
    for k, v in copied.items():
        print(f"   {k:10s} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
