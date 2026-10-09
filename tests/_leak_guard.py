#!/usr/bin/env python3
"""The identifier-leak guard — the one scanner behind every "no real topology / no personal identifier" gate.

Two layers, one loader (design: docs/reviews/2026-10-08-public-split-pii-sweep/99-synthesis.md, SECURITY.md C21):

  1. STRUCTURAL (always on, public, carries no instance knowledge). Flags identifiers that can never legitimately
     appear in the shippable tree, by SHAPE: an RFC-1918 IPv4 in ANY separator form (dotted, dashed as the capture
     filenames spell it, underscored), a non-documentation MAC (anything but the RFC-7042
     `00:00:5e:00:53:xx` range / null / broadcast — colon, dash, dotted-Cisco and space-hex forms), a non-documentation
     global IPv6 (outside RFC-3849 `2001:db8::/32`), a real-length age recipient or AGE secret key, the maintainer's
     personal email, and an operator-machine user-profile path. RFC-5737 TEST-NET (`192.0.2/24`, `198.51.100/24`,
     `203.0.113/24`) is the sanctioned example space and never matches. Version strings, OIDs (5+-group dotted runs)
     and documentation addresses are stripped before matching so the gate under-fires rather than cries wolf.

  2. INSTANCE TOKENS (private, optional). The literal names that identify ONE deployment (its hostnames, domain,
     user names) are themselves identifiers, so they are never written into this public file. They are read, one
     regex per line, from the first readable source: `$KONTROLL_LEAK_TOKENS_FILE` (CI injects a secret here), else
     `instance/leak-tokens.txt` (the private overlay — stripped from the public cut, the bundle and the launch kit),
     else `instance.example/leak-tokens.example.txt` (synthetic CANARIES, so the mechanism is always exercised and a
     scan that finds nothing is never a scan that ran nothing). A matched token is reported as `token#N` plus an
     8-hex sha256 — a failure log must never itself be the leak.

Escape hatch: a same-line `pii-guard: allow <reason>` marker exempts that line (review-visible in the diff).

Usage (the SAME scan runs locally, on the VM, in the private CI and in the public CI — tests/validate.sh step
`pii-guard`, .github/workflows/pii-guard.yml, and the pytest twin tests/unit/test_leak_guard.py):
    python3 tests/_leak_guard.py --tree [ROOT]              # every git-tracked file minus the private strip set
    python3 tests/_leak_guard.py --scope PATH [PATH ...]    # just these files/dirs (validate's P-1 discovery leg)
Exit 1 on any finding, 2 when the tree could not be enumerated (fail closed).
"""
import hashlib
import ipaddress
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The private strip set — exactly what scripts/make-bundle.sh removes from the public bundle and what the public
# split cut (docs/public-split.md) leaves out; plus the git-ignored local/ in case it is ever force-added.
STRIP_DIRS = ("instance/", "docs/reviews/", "local/")
# The guard's own unit test holds identifier-SHAPED samples (private-range addresses, MAC forms, a user-profile
# path) by necessity; it is the one tracked file the tree scan skips. It uses no real deployment's values and is
# reviewed as the guard's specification.
SELF_TEST = "tests/unit/test_leak_guard.py"
ALLOW_MARK = "pii-guard: allow"
MAX_BYTES = 8_000_000

# --- layer 1: structural -------------------------------------------------------------------------------------
_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# any-separator IPv4: the separator is captured once and must repeat (so `192.168.1-2` is not a match)
# lookbehind/lookahead allow `_` (capture filenames spell `<class>_<a>-<b>-<c>-<d>.cfg`) but refuse a continuing
# digit run on the same separator (so a 5th group is never half-matched) and any letter/digit glued on.
_IPV4_ANY = re.compile(r"(?<![A-Za-z0-9.:-])(" + _OCT + r")([.\-_])(" + _OCT + r")\2(" + _OCT + r")\2(" + _OCT + r")"
                       r"(?![A-Za-z0-9])(?!\2\d)")
# RFC 1918 named explicitly: ipaddress.is_private is ALSO true for the RFC-5737 documentation nets (they are IANA
# special-purpose), which are exactly the sanctioned example space — so is_private would flag every TEST-NET example.
# Built from integers so this file carries no private-range literal of its own (it is scanned like every other file).
_RFC1918 = [ipaddress.ip_network((0x0A000000, 8)), ipaddress.ip_network((0xAC100000, 12)),
            ipaddress.ip_network((0xC0A80000, 16))]
_OID_RUN = re.compile(r"\d+(?:\.\d+){4,}")                          # a bare OID / 5+-group dotted run: never an IPv4
_VERSION_PREFIX = re.compile(r"(?i)(?:\bv|version\s*|release\s*|[=~<>]=?\s*)$")
_MAC = re.compile(r"(?<![A-Za-z0-9:.-])(?:[0-9A-Fa-f]{2}([:\-])){5}[0-9A-Fa-f]{2}(?![A-Za-z0-9:.-])"
                  r"|(?<![\w.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![\w.])"
                  r"|(?<![\w:])(?:[0-9A-Fa-f]{2} ){5}[0-9A-Fa-f]{2}(?![\w:])")
_IPV6 = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f:]*::|(?:[0-9A-Fa-f]{1,4}:){2})"
                   r"(?:[0-9A-Fa-f]{1,4}:){1,7}(?::?[0-9A-Fa-f]{1,4}){0,7}(?![\w:.])")
_AGE_PUB = re.compile(r"\bage1[02-9ac-hj-np-z]{58}\b")              # a REAL-length recipient (the placeholder is shorter)
_AGE_SECRET = re.compile(r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b")
# The personal identifiers use character classes so this public file never spells them out (and never matches
# itself) — the same device netcanon's PII guard uses. Both forms of the user-profile path (the drive-letter form with
# one or many separators, and the MSYS mount form) are covered.
_PERSONAL = re.compile(r"(?i)samuelr[i]pp09|[a-z]:[\\/]+[u]sers[\\/]+|/c/[u]sers/")
_DOC_V6 = ipaddress.ip_network("2001:db8::/32")


def _norm_mac(tok):
    t = tok.lower().replace("-", ":").replace(" ", ":")
    if "." in t:
        h = t.replace(".", "")
        t = ":".join(h[i:i + 2] for i in range(0, 12, 2))
    return t


_MAC_PLACEHOLDERS = ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55",
                     "01:23:45:67:89:ab", "11:22:33:44:55:66")


def _mac_is_doc(tok):
    """RFC-7042 documentation MACs, the null/broadcast addresses and the obvious textbook placeholders (a docstring's
    `aa:bb:cc:dd:ee:ff`) are not identifiers."""
    t = _norm_mac(tok)
    return t.startswith("00:00:5e:00:53:") or t.startswith("de:ad:be:ef:") or t in _MAC_PLACEHOLDERS


def structural_findings(text, path=""):
    """[(lineno, category, token)] for every structural identifier in `text`. `token` is the matched text —
    these are SHAPE classes (private IP, MAC, …), not instance names, so showing them is not itself a leak."""
    out = []
    for ln, line in enumerate(text.split("\n"), 1):
        if ALLOW_MARK in line:
            continue
        for m in _PERSONAL.finditer(line):
            out.append((ln, "personal-identifier", m.group(0)))
        scan = _OID_RUN.sub(" ", line)                               # drop OIDs before the IPv4 pass
        for m in _IPV4_ANY.finditer(scan):
            if _VERSION_PREFIX.search(scan[max(0, m.start() - 10):m.start()]):
                continue
            try:
                ip = ipaddress.ip_address(".".join(m.group(1, 3, 4, 5)))
            except ValueError:
                continue
            if any(ip in net for net in _RFC1918):
                out.append((ln, "rfc1918-ipv4", m.group(0)))
        for m in _MAC.finditer(line):
            if not _mac_is_doc(m.group(0)):
                out.append((ln, "mac", m.group(0)))
        for m in _IPV6.finditer(line):
            tok = m.group(0)
            if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", tok) or re.fullmatch(r"[\d:]+", tok):
                continue                                             # a MAC (handled above) / a time-like digit run
            try:
                ip = ipaddress.ip_address(tok)
            except ValueError:
                continue
            # is_global alone is not enough: Python reports multicast (ff02::1) as global on some versions.
            if (not (ip.is_multicast or ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_private)
                    and ip not in _DOC_V6):
                out.append((ln, "ipv6-global", tok))
        for m in _AGE_PUB.finditer(line):
            out.append((ln, "age-recipient", m.group(0)[:12] + "…"))
        for m in _AGE_SECRET.finditer(line):
            out.append((ln, "age-secret-key", "AGE-SECRET-KEY-1…"))
    return out


# --- layer 2: instance tokens ------------------------------------------------------------------------------------
def tokens_source(root=ROOT):
    """The path the instance-token layer reads, in precedence order (env → private overlay → shipped canaries),
    or None when none exists. Exposed so a caller can say WHICH layer ran."""
    env = os.environ.get("KONTROLL_LEAK_TOKENS_FILE")
    for cand in (env, os.path.join(root, "instance", "leak-tokens.txt"),
                 os.path.join(root, "instance.example", "leak-tokens.example.txt")):
        if cand and os.path.isfile(cand):
            return cand
    return None


def instance_patterns(root=ROOT):
    """Compiled, case-insensitive, word-bounded regexes from tokens_source() — one per non-comment line. The
    canary file is the floor: with no private list the layer still runs (and the self-test proves it fires)."""
    src = tokens_source(root)
    if src is None:
        return []
    pats = []
    with open(src, encoding="utf-8") as fh:
        for raw in fh:
            tok = raw.strip()
            if not tok or tok.startswith("#"):
                continue
            pats.append(re.compile(r"(?i)(?<![\w-])(?:%s)(?![\w-])" % tok))
    return pats


def token_findings(text, patterns):
    """[(lineno, 'instance-token', 'token#N sha256:xxxxxxxx')] — NEVER the matched value (the report must not be
    the leak). `patterns` is instance_patterns(); the index N is the token's line order in the private file."""
    out = []
    for ln, line in enumerate(text.split("\n"), 1):
        if ALLOW_MARK in line:
            continue
        for n, pat in enumerate(patterns, 1):
            m = pat.search(line)
            if m:
                digest = hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:8]
                out.append((ln, "instance-token", "token#%d sha256:%s" % (n, digest)))
    return out


# --- the tree scan -----------------------------------------------------------------------------------------------
def shippable_files(root=ROOT):
    """Every git-tracked file under `root` minus the private strip set. Fails closed (raises) if git cannot list."""
    r = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True)
    files = [f for f in r.stdout.decode("utf-8", errors="replace").split("\0") if f]
    return [f for f in files if not f.startswith(STRIP_DIRS) and f != SELF_TEST]


def scan_paths(paths, root=ROOT, patterns=None):
    """[(path, lineno, category, token)] over `paths` (files, or dirs walked). Binary / oversize files skipped."""
    pats = instance_patterns(root) if patterns is None else patterns
    src = tokens_source(root)
    out = []
    for rel in paths:
        full = os.path.join(root, rel)
        if src and os.path.abspath(full) == os.path.abspath(src):
            continue                                                 # the token list names its own tokens, by design
        if os.path.isdir(full):
            for dp, _, fns in os.walk(full):
                out.extend(scan_paths([os.path.relpath(os.path.join(dp, fn), root) for fn in sorted(fns)], root, pats))
            continue
        try:
            b = open(full, "rb").read()
        except OSError:
            continue
        if b"\0" in b[:8192] or len(b) > MAX_BYTES:
            continue
        text = b.decode("utf-8", errors="replace")
        rel = rel.replace(os.sep, "/")
        for ln, cat, tok in structural_findings(text, rel) + token_findings(text, pats):
            out.append((rel, ln, cat, tok))
    return out


def main(argv):
    if argv[:1] == ["--tree"]:
        root = os.path.abspath(argv[1]) if len(argv) > 1 else ROOT
        try:
            paths = shippable_files(root)
        except (subprocess.CalledProcessError, OSError) as exc:
            print("pii-guard: cannot enumerate tracked files (%s) — failing closed" % exc, file=sys.stderr)
            return 2
    elif argv[:1] == ["--scope"] and len(argv) > 1:
        root, paths = ROOT, argv[1:]
    else:
        print(__doc__, file=sys.stderr)
        return 2
    src = tokens_source(root)
    findings = scan_paths(paths, root)
    for rel, ln, cat, tok in findings:
        print("%s:%d  %s  %s" % (rel, ln, cat, tok))
    layer2 = "none" if src is None else ("env" if src == os.environ.get("KONTROLL_LEAK_TOKENS_FILE")
                                         else "instance/" if "instance" + os.sep + "leak-tokens" in src or "instance/leak-tokens" in src
                                         else "canaries")
    print("pii-guard: %d finding(s) in %d file(s); instance-token layer = %s" % (len(findings), len(paths), layer2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
