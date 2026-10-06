"""Pull the encryptor's string literals out of the Ghidra dump we already have.

FindEncryptKey.java answers one question: which functions reference the
"pes-custom-encrypt" header region, and what string literals do they load?
It only println()s, so its answer would land in a runner's log -- but the same
answer is derivable from full1/fulldump_out.txt, which we already hold.

A STR line carries one literal and ANY number of xrefs:

    STR <str_addr> <text> |<xref>@<sym> |<xref>@<sym> ...

so it is parsed by scanning for every "|<hex>@<sym>" group from the right, not
by expecting exactly one at the end (the header line carries eight).

Four views, printed side by side:

  A. literal-pool neighbours -- literals whose OWN address sits within +-0x4000
     of the header.  AArch64 ADRP/ADD pairs address one page window, so literals
     packed beside the header are loaded by the same code that names it.
  B. exact-site literals     -- strings referenced at each of the eight known
     xref sites, i.e. loaded by that very code point.
  C. covering functions      -- group literals by their attributed symbol and
     dump every literal of any function whose span contains a known site.
  D. crypto-shaped literals  -- anything mentioning aes/cbc/iv/key/pad/...

Addresses: the dump is ELF VA + 0x100000 (proven: ELF 0x7b38a44 sign builder
-> dump FUN_07c38a44; and here dump 0x00bd120e -> ELF 0x00ad120e, matching the
comment in FindEncryptKey.java).  All eight sites share one PT_LOAD, so a
single delta is valid for them -- it is never applied across a segment edge.

Output goes to a UTF-8 file because the console is cp1252.
"""
import re

DUMP = r"C:\Users\Administrator\AppData\Local\Temp\2\full1\fulldump_out.txt"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\enc_scan.txt"

DELTA = 0x100000

# xrefs to "pes-custom-encrypt", as ELF VAs (already recorded in this project)
SITES_ELF = [0x7B23164, 0x7B2EB78, 0x7B34D18, 0x7B35CF4,
             0x7B36BA8, 0x7B39120, 0x7EC024C, 0x7ECAD64]
SITES = [s + DELTA for s in SITES_ELF]

XREF_RE = re.compile(rb"\|([0-9a-f]{8})@(\S+)")
KEYISH = re.compile(rb"(aes|cbc|ecb|gcm|blowfish|sha|md5|hmac|iv_|pad|key|"
                    rb"encrypt|decrypt|256|128|pkcs)", re.I)

out = []


def say(s=""):
    out.append(str(s))


def vis(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)[:70]


# ---------------------------------------------------------------- parse -----
rows = []           # (str_addr, text, [(xref, sym), ...])
n_lines = 0
str_started = False
header = None       # (str_addr, text, xrefs)

with open(DUMP, "rb") as fh:
    for raw in fh:
        n_lines += 1
        if not str_started:
            if raw.startswith(b"=== STRINGS ==="):
                str_started = True
            continue
        line = raw.rstrip(b"\r\n")
        if not line.startswith(b"STR "):
            continue
        body = line[4:]
        if len(body) < 9 or body[8:9] != b" ":
            continue
        try:
            sa = int(body[:8], 16)
        except ValueError:
            continue
        xrefs = [(int(m.group(1), 16), m.group(2).decode("ascii", "replace"))
                 for m in XREF_RE.finditer(body)]
        first = XREF_RE.search(body)
        if first is None:
            continue
        text = body[9:first.start()].rstrip()
        rec = (sa, text, xrefs)
        rows.append(rec)
        if text == b"pes-custom-encrypt":
            header = rec

say("dump file          : %s" % DUMP)
say("total lines        : %d" % n_lines)
say("STR rows parsed    : %d" % len(rows))
say("STRINGS section on : %s" % ("yes" if str_started else "NO"))
if header is None:
    say("header literal      : NOT FOUND -> abort")
    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    raise SystemExit(1)

h_addr, _, h_xrefs = header
# Take the sites straight from the dump rather than deriving them.  The
# recorded site list is mixed: six entries were ELF VAs (dump = +0x100000) but
# 0x7ec024c / 0x7ecad64 were already dump addresses, so adding the delta to
# those produced 0x07fc024c / 0x07fcad64 -- addresses that do not exist.  The
# dump line itself is authoritative.
SITES = [x for x, _ in h_xrefs]
say("header literal      : dump 0x%08x  (%d xrefs)" % (h_addr, len(h_xrefs)))
for xa, sym in h_xrefs:
    say("                      xref 0x%08x @ %s" % (xa, sym))
say("ELF (dump-0x100000) : %s"
    % ", ".join("0x%08x" % (x - DELTA) for x, _ in h_xrefs))
say("")

# --------------------------------------------------- A. pool neighbours -----
lo, hi = h_addr - 0x4000, h_addr + 0x4000
pool = sorted((r for r in rows if lo <= r[0] <= hi), key=lambda r: r[0])
say("=" * 78)
say("A. LITERALS WITHIN +-0x4000 OF THE HEADER  (%d)" % len(pool))
say("=" * 78)
for sa, text, xrefs in pool:
    say("  0x%08x  %-70s  via %s"
        % (sa, vis(text),
           ",".join("0x%08x@%s" % (x, s) for x, s in xrefs[:3])))
say("")

# -------------------------------------------------- B. exact-site literals --
say("=" * 78)
say("B. LITERALS REFERENCED AT EACH KNOWN SITE")
say("=" * 78)
by_xref = {}
for sa, text, xrefs in rows:
    for xa, sym in xrefs:
        by_xref.setdefault(xa, []).append((sa, text, sym))
for elf_s, site in zip(SITES_ELF, SITES):
    got = by_xref.get(site, [])
    say("")
    say("  site ELF 0x%08x / dump 0x%08x  ->  %d literal(s)"
        % (elf_s, site, len(got)))
    for sa, text, sym in got:
        say("      0x%08x  %-70s  @ %s" % (sa, vis(text), sym))
say("")

# -------------------------------------------------- C. covering functions ---
groups = {}
for sa, text, xrefs in rows:
    for xa, sym in xrefs:
        g = groups.setdefault(sym, [xa, xa, []])
        g[0] = min(g[0], xa)
        g[1] = max(g[1], xa)
        g[2].append((xa, sa, text))

covering = [(sym, g) for sym, g in groups.items()
            if any(g[0] <= s <= g[1] for s in SITES)]
covering.sort(key=lambda t: t[1][0])

say("=" * 78)
say("C. FUNCTIONS WHOSE XREF SPAN COVERS A KNOWN SITE  (%d)" % len(covering))
say("=" * 78)
for sym, g in covering:
    say("")
    say("--- %s   span 0x%08x .. 0x%08x   (%d literals)"
        % (sym, g[0], g[1], len(g[2])))
    seen = set()
    shown = 0
    for xa, sa, text in sorted(g[2]):
        k = (sa, text)
        if k in seen:
            continue
        seen.add(k)
        if shown >= 80:
            say("      ... %d more in this function not printed"
                % (len(seen) - 80))
            break
        shown += 1
        say("      0x%08x  0x%08x  %s" % (xa, sa, vis(text)))
say("")

# --------------------------------------------- E. gate-code window, by func --
# The single xref sites only reveal the header load itself.  What the
# encryptor also loads shows up as the OTHER string references inside the same
# window.  Two windows cover all eight sites (dump coords).
WINDOWS = [
    ("gate/sign region", 0x07C18000, 0x07C44000),
    ("second cluster",   0x07EB8000, 0x07ED8000),
]
say("")
say("=" * 78)
say("E. STRING XREFS IN THE GATE WINDOWS, GROUPED BY FUNCTION SYMBOL")
say("=" * 78)
for label, wlo, whi in WINDOWS:
    win = {}
    for sa, text, xrefs in rows:
        for xa, sym in xrefs:
            if wlo <= xa <= whi:
                g = win.setdefault(sym, [xa, xa, []])
                g[0] = min(g[0], xa)
                g[1] = max(g[1], xa)
                g[2].append((xa, sa, text))
    say("")
    say("--- window %s  dump 0x%08x .. 0x%08x  : %d symbol(s)"
        % (label, wlo, whi, len(win)))
    for sym in sorted(win, key=lambda s: win[s][0]):
        g = win[sym]
        say("")
        say("  %s   span 0x%08x .. 0x%08x   (%d literal refs)"
            % (sym, g[0], g[1], len(g[2])))
        seen, shown = set(), 0
        for xa, sa, text in sorted(g[2]):
            if (sa, text) in seen:
                continue
            seen.add((sa, text))
            if shown >= 40:
                say("      ... %d more not printed" % (len(seen) - 40))
                break
            shown += 1
            say("      0x%08x  0x%08x  %s" % (xa, sa, vis(text)))

# ------------------------------------------------- D. crypto-shaped --------
hits = [r for r in rows if KEYISH.search(r[1])]
say("=" * 78)
say("D. CRYPTO/KEY-SHAPED LITERALS ANYWHERE IN THE DUMP  (%d)" % len(hits))
say("=" * 78)
for sa, text, xrefs in hits[:150]:
    say("  0x%08x  %-70s  via %s"
        % (sa, vis(text),
           ",".join("0x%08x@%s" % (x, s) for x, s in xrefs[:3])))
if len(hits) > 150:
    say("  ... %d more not printed" % (len(hits) - 150))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
