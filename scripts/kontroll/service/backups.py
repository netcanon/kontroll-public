"""backups — the read-only per-device backup INDEX / VIEW / DIFF over the captures git store (C8/C14).

A PURE READ of the local-only, secret-bearing captures git store (the same `0700`/uid-1001 dir the
backup-configs.yml snapshot play versions; SECURITY.md C8). Mirrors service/fleet.py's posture: it NEVER raises out
to the in-process Flask worker and NEVER `sys.exit`s (that would kill the worker — the in-process-service
INVARIANT). A missing dir / `.git` yields `{available: false}` with a reason, NOT a crash and NOT an empty-success
that reads as "this device has no config".

DISTINCT from service/backup.py — that is the capability BUILDER that WRITES the `backup:` block + regenerates the
schedule spec (the propose/promote path). THIS module is the read-only VIEWER of the capture history. They share a
name root and the C8/C14 concern, nothing else; see backup.py's header for the reciprocal pointer.

SECURITY (C14 — the load-bearing contract):
  * Read-only BY CONSTRUCTION: it shells only `git log/show/diff/ls-files` — NO write verb anywhere. A grep/AST
    pin (tests/unit/_readonly_pins.assert_no_git_write) fails CI if a mutating subcommand ever appears here.
  * The captures dir is mounted `:ro` into onboard-gui (docker/services/onboard-gui.yaml) — a GUI RCE can READ,
    never rewrite/`git rm` the secret history.
  * STRICT input validation BEFORE any `git show`: `rev` is a 7–40-hex SHA; `file` must be a MEMBER of the store's
    own index allow-list (the set of names the store actually contains — strictly stronger than a path regex);
    `--` precedes every path arg; subprocess is an argv LIST (never `shell=True`); output is byte-bounded.
  * The served text is REDACTED server-side (config/capture-redactions.yml) before it leaves the process, and the
    diff runs on the REDACTED text (redact-then-diff) so a pure-secret change shows masked-vs-masked. Redaction is
    DEFENSE-IN-DEPTH, **not the boundary** — the boundary is the GUI's auth + TLS + mgmt-VLAN bind (C3) + the `:ro`
    mount. A vendor secret token shape not in the registry can still leak into the in-browser view (the accepted,
    documented residual — SECURITY.md C14 names the FortiGate `ENC` view-only case concretely).
  * Behind the GUI's inherited fail-closed gate; every view/diff read writes a NAMES-only audit line (the route's
    job — file + rev, never a capture value).

See SECURITY.md C14, docs/reviews/2026-06-19-gui-backup-index-diff/21-design-backup-index-view-diff.md.
"""
import difflib
import logging
import os
import re
import subprocess

import yaml

from kontroll import paths

log = logging.getLogger("kontroll.service.backups")


class BackupStoreError(Exception):
    """A git/read failure inside the captures store. Caught by the route → a clean 400/500. NEVER sys.exit."""


_CAP_ENV = "KONTROLL_CAPTURES_DIR"                  # the in-container :ro bind path the service reads (e.g. /backups).
# NB deliberately DISTINCT from the .env `KONTROLL_BACKUPS_DIR` (the HOST path the compose volume interpolates) —
# a same-name var would alias the host path and the container path across two scopes. The compose file sets
# KONTROLL_CAPTURES_DIR=/backups explicitly; a test points it at a throwaway git repo.
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")           # a rev id from the index (short or full); reject anything else.
_TIMEOUT = 10                                       # seconds — the store is a local repo; a hang is a bug.
_MAX_BYTES = 2 * 1024 * 1024                        # 2 MB ceiling on any single show/diff blob (DoS guard).
_MAX_LOG = 500                                      # cap git-log depth (a runaway history can't blow the payload).
_MAX_VIEW_LINES = _MAX_LOG * 20                     # 10k-line ceiling on a single rendered config (view truncation).

# READ-ONLY git subcommands this module is allowed to shell. The argv-based git-write pin
# (tests/unit/_readonly_pins.assert_no_git_write) asserts every `git` call here uses one of these — a `git
# rm`/`commit`/`update-ref` would ride a subprocess arg list past a call-NAME check, so it is pinned on the verb.
READONLY_GIT = frozenset({"log", "show", "diff", "ls-files", "rev-parse", "cat-file", "for-each-ref"})

_RED_CACHE = {}                                     # path -> compiled [(pattern, mask, subject)]; tiny file, cache it.


# --------------------------------------------------------------------------- store resolution + the absent guard --

def _cap_dir():
    """Resolve the captures dir from the env seam — never hard-code. In-container this is the `:ro` bind path
    (KONTROLL_CAPTURES_DIR=/backups); a test points KONTROLL_CAPTURES_DIR at a throwaway git repo."""
    return os.environ.get(_CAP_ENV)


def store_state():
    """{available, reason, cap_dir} — the fail-closed-but-graceful guard. An absent var / not-a-dir / no `.git` all
    degrade to available=false with a reason. NEVER raises; the route is already auth'd so the reason may name the
    dir for the operator. A fresh node without the captures mount makes the feature INERT, not broken."""
    cap = _cap_dir()
    if not cap or not os.path.isdir(cap):
        return {"available": False, "reason": "captures store not mounted", "cap_dir": cap}
    if not os.path.isdir(os.path.join(cap, ".git")):
        return {"available": False, "reason": "no capture history yet", "cap_dir": cap}
    return {"available": True, "reason": None, "cap_dir": cap}


# --------------------------------------------------------------------------------------- the git plumbing (read) --

def _git(cap, args, *, bounded=True):
    """`subprocess.run(['git','-C',cap, *args])` — an argv LIST (never shell=True), `-C` not `cd`, a short timeout,
    an output ceiling. Raises BackupStoreError on non-zero/timeout/oversize. NEVER echoes git's stderr to the
    caller (it can carry the host path). `args[0]` must be a READONLY_GIT verb (pinned in CI)."""
    try:
        p = subprocess.run(["git", "-C", cap, *args], capture_output=True, text=True, timeout=_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise BackupStoreError("git failed: %s" % type(e).__name__)
    if p.returncode != 0:
        raise BackupStoreError("git rc=%d" % p.returncode)          # never surface p.stderr (path leak)
    if bounded and len(p.stdout) > _MAX_BYTES:
        raise BackupStoreError("output exceeds %d bytes" % _MAX_BYTES)
    return p.stdout


def _is_capture_file(fn):
    """True if `fn` is a real capture filename, not a dot/meta file (`.gitignore`, `.gitattributes`, `.git`). The
    capture roles write `<Label>_<host>.<ext>`; nothing legitimate starts with a dot. The store's own `.gitignore`
    (committed by backup-configs.yml to carry the capture-exception excludes) is therefore kept out of BOTH the
    device index AND the allow-list — so it never shows as a bogus 'device' row, nor is it viewable/diffable."""
    return not fn.startswith(".")


def _tracked_files(cap):
    """The history-eligible capture files (the allow-list every file arg is validated against). `git ls-files`,
    minus dot/meta files (`.gitignore`) — symmetric with `_ondisk_files`, so a committed meta file is neither
    indexed nor accepted by `_validate_file`. Unbounded — it is a file-NAME list (metadata), not a blob; the
    _MAX_BYTES ceiling guards the `show` reads."""
    return {fn for fn in _git(cap, ["ls-files"], bounded=False).splitlines() if _is_capture_file(fn)}


def _ondisk_files(cap):
    """Working-tree capture files (includes excluded/latest-only ones, e.g. FortiGate_*). Excludes dot/meta files
    (`.git`, `.gitignore`) via the shared `_is_capture_file` predicate."""
    return {fn for fn in os.listdir(cap)
            if _is_capture_file(fn) and os.path.isfile(os.path.join(cap, fn))}


# ----------------------------------------------------------------------------------------- input validation (M2) --

def _validate_rev(rev):
    """A rev MUST be a 7–40-hex SHA from the index — reject `../`, a `-flag`, a ref name, a range, an injection.
    Called FIRST (before the allow-list build) so a crafted rev never reaches `git show`."""
    if not isinstance(rev, str) or not _SHA_RE.match(rev):
        raise BackupStoreError("invalid rev")


def _validate_file(cap, file):
    """A file MUST be a MEMBER of the store's own index allow-list (tracked OR on-disk) — strictly stronger than a
    path-sanity regex: no `..`, `/`, leading `-`, or NUL can be a real capture filename, and even if one were it
    would have to already exist in the store. This is THE path-traversal mitigation (review M2); it runs BEFORE any
    `git show` so a bad file is rejected before it can reach the blob read."""
    if not isinstance(file, str) or file not in (_tracked_files(cap) | _ondisk_files(cap)):
        raise BackupStoreError("unknown capture file")


# ----------------------------------------------------------------------------------------------- redaction (C14) --

def _redactions_path():
    # config/ is config-as-data in the canonical/clone (regen target, NOT baked into the control image), so read it
    # from write_root() — in a baked deploy paths.ROOT is the read-only image at /opt/kontroll, which has no config/.
    return os.path.join(paths.write_root(), "config", "capture-redactions.yml")


def _load_redactions():
    """Load + compile config/capture-redactions.yml (cached by path). A malformed file / entry is SKIPPED with a
    warning (never blanks the whole filter — the skip-malformed posture). Each pattern MUST have EXACTLY ONE
    capturing group = the secret span; an entry that doesn't is skipped (a bad regex must not silently no-op the
    mask or, worse, mask the wrong span). Read-only registry; redaction is defense-in-depth, not the boundary."""
    path = _redactions_path()
    if path in _RED_CACHE:
        return _RED_CACHE[path]
    compiled = []
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh.read()) or {}
        for entry in (doc.get("redactions") or []):
            try:
                pat = re.compile(entry["pattern"])
            except (re.error, KeyError, TypeError):
                log.warning("backups: skipping malformed redaction entry %r", entry)
                continue
            if pat.groups != 1:
                log.warning("backups: redaction %r must have exactly ONE capturing group (the secret); skipping",
                            entry.get("subject"))
                continue
            compiled.append((pat, entry.get("mask", "‹redacted›"), entry.get("subject", "?")))
    except (OSError, yaml.YAMLError) as e:
        log.warning("backups: capture-redactions.yml unreadable (%s) — serving UNREDACTED is unsafe, so redact() "
                    "treats an unreadable registry as 'mask nothing but flag redacted=unknown'", type(e).__name__)
        return None                                  # sentinel: registry unavailable (redact() fails toward caution)
    _RED_CACHE[path] = compiled
    return compiled


def redact(text):
    """Apply the compiled registry to `text`; return (redacted_text, redacted_bool). Only the single capturing
    group (the secret span) of each match is replaced with the mask — the line STRUCTURE stays legible
    (`username admin secret 9 ‹redacted›`) so the diff stays useful. REDACT-THEN-DIFF is the rule (diff runs on the
    output of this), so a pure-secret change shows masked-vs-masked, never leaking that *a* secret changed.

    HONEST LIMIT: a token shape not in the registry passes through unmasked — defense-in-depth, NOT a guarantee
    (SECURITY.md C14 residual). If the registry is UNREADABLE the text is returned unchanged with redacted=True
    (the flag stays truthy so the UI keeps the "secrets masked (best-effort)" caveat — we never silently claim a
    clean read when the masker failed to load)."""
    reg = _load_redactions()
    if reg is None:
        return text, True                            # registry unavailable → flag redacted, don't claim a clean view
    out = text
    hit = False
    for pat, mask, _subj in reg:
        def _mask_group(m, _mask=mask):
            s, e = m.start(1) - m.start(0), m.end(1) - m.start(0)
            if e <= s:                               # empty capture → leave the line untouched
                return m.group(0)
            return m.group(0)[:s] + _mask + m.group(0)[e:]
        out, n = pat.subn(_mask_group, out)
        hit = hit or bool(n)
    return out, hit


# ------------------------------------------------------------------------------------------ the device→file glue --

_DASHED_IP = re.compile(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}")


def _split_capture_name(fn):
    """Best-effort (label, host_key) from a capture filename. The live roles write STABLE per-host names:
    `<label>_<host-dashed>.cfg` (CLI), `OPNsense_<host-dashed>_config.xml`, `RouterOS_<host-dashed>_export.rsc`,
    and inventory-name forms (`Proxmox_<name>_node-and-guests.txt`). host_key = the dashed-IP segment if present
    (cosmetic only — the FILE is the index key, not this). Tolerates the no-dashed-IP case (host_key='')."""
    stem = re.sub(r"\.(cfg|conf|xml|rsc|txt|bak|json|yml|yaml)$", "", fn, flags=re.I)
    m = _DASHED_IP.search(stem)
    host_key = m.group(0) if m else ""
    label = stem[: m.start()].rstrip("_-") if m else stem
    return (label or stem), host_key


# ---------------------------------------------------------------------------------------------- the four reads --

def _log(cap, file):
    """`git log --follow` for one validated capture file (newest first) → [{rev, short, iso, subject}]. `--` before
    the path; bounded depth. The file is validated by allow-list membership first."""
    _validate_file(cap, file)
    raw = _git(cap, ["log", "--follow", "-n", str(_MAX_LOG), "--format=%H%x09%cI%x09%s", "--", file], bounded=False)
    rows = []
    for line in raw.splitlines():
        parts = line.split("\t", 2)
        h = parts[0]
        if h:
            rows.append({"rev": h, "short": h[:7], "iso": parts[1] if len(parts) > 1 else "",
                         "subject": parts[2] if len(parts) > 2 else ""})
    return rows


def list_devices(host=None):
    """The capture-bearing devices for the index — one entry per capture FILE (on disk and/or in history). With
    `host` (a dotted ansible_host) given, filter to files whose name carries the DASHED host (the per-host
    drill-in). Returns {available, reason, devices:[{file, label, host_key, rev_count, latest:{rev,short,iso}|None,
    diffable}]}. diffable=false ⇒ an excluded (capture-exception) file — on disk, no history (e.g. FortiGate)."""
    st = store_state()
    if not st["available"]:
        return {"available": False, "reason": st["reason"], "devices": []}
    cap = st["cap_dir"]
    tracked, ondisk = _tracked_files(cap), _ondisk_files(cap)
    needle = host.replace(".", "-") if host else None
    out = []
    for fn in sorted(ondisk | tracked):
        label, host_key = _split_capture_name(fn)
        # EXACT dashed-host match on the parsed host_key — NOT a substring (a substring `192-0-2-1` would also
        # match `…_192-0-2-12.cfg`, over-listing a neighbouring host's capture). The header flat list (no host)
        # surfaces the inventory-name forms (Proxmox/Docker) that have no dashed-IP host_key.
        if needle and host_key != needle:
            continue
        diffable = fn in tracked
        revs = _log(cap, fn) if diffable else []
        out.append({"file": fn, "label": label, "host_key": host_key,
                    "rev_count": len(revs), "diffable": diffable,
                    "latest": ({"rev": revs[0]["rev"], "short": revs[0]["short"], "iso": revs[0]["iso"]}
                               if revs else None)})
    return {"available": True, "reason": None, "devices": out}


def for_host(ansible_host):
    """Map a Fleet host (dotted ansible_host) to its capture device entries — list the store + match the DASHED
    host. A thin wrapper over list_devices(host=…) so the brittle host→file matching stays SERVER-side. Tolerates
    label drift + multiple captures per host; misses the inventory-name forms (Proxmox/Docker use inventory_hostname,
    not the dashed IP) — the header flat list (no host) surfaces those."""
    return list_devices(host=ansible_host)


def list_versions(file):
    """The per-device VERSION LIST. {available, reason, file, diffable, revisions:[{rev,short,iso,subject}], note}.
    Empty + on-disk ⇒ note='latest only — excluded from history'; empty + absent ⇒ 'no history for this device yet'.
    `file` is validated by allow-list membership in _log()."""
    st = store_state()
    if not st["available"]:
        return {"available": False, "reason": st["reason"], "revisions": []}
    cap = st["cap_dir"]
    revs = _log(cap, file)
    diffable = file in _tracked_files(cap)
    note = None
    if not revs:
        note = "latest only — excluded from history" if file in _ondisk_files(cap) else "no history for this device yet"
    return {"available": True, "file": file, "diffable": diffable, "revisions": revs, "note": note}


def get_version(file, rev):
    """A single rev's REDACTED text. `git show <rev>:<file>` (both pre-validated; not a path arg), redact, split to
    bounded lines. {available, file, rev, redacted, lines:[...], truncated, note}. Validation runs BEFORE the
    `git show` (M2): a bad rev/file raises here, never reaching the blob read."""
    st = store_state()
    if not st["available"]:
        return {"available": False, "reason": st["reason"], "lines": []}
    cap = st["cap_dir"]
    _validate_rev(rev)
    _validate_file(cap, file)
    raw = _git(cap, ["show", "%s:%s" % (rev, file)])            # rev:file, both pre-validated; `:` is not a path
    text, redacted = redact(raw)                                # REDACT before the bytes leave the process
    lines = text.splitlines()
    truncated = len(lines) > _MAX_VIEW_LINES
    return {"available": True, "file": file, "rev": rev, "redacted": redacted,
            "lines": lines[:_MAX_VIEW_LINES], "truncated": truncated, "note": None}


def _difflib_hunks(a_lines, b_lines):
    """Parse `difflib.unified_diff(a, b, n=3)` into structured hunks the dumb client renderer paints. Returns
    (hunks, stats): each hunk = {header, lines:[{t ∈ ctx|add|del, ol, nl, text}]} (ol/nl reconstructed from the
    `@@ -a,b +c,d @@` arithmetic), stats = {added, removed}. The ONE 'parse a diff' routine — in Python, with a
    docstring + unit test, never in the untested browser."""
    hunks, cur = [], None
    ol = nl = added = removed = 0
    hdr = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    for line in difflib.unified_diff(a_lines, b_lines, n=3, lineterm=""):
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        m = hdr.match(line)
        if m:
            ol, nl = int(m.group(1)), int(m.group(2))
            cur = {"header": line, "lines": []}
            hunks.append(cur)
            continue
        if cur is None:
            continue
        tag, body = line[:1], line[1:]
        if tag == "+":
            cur["lines"].append({"t": "add", "ol": None, "nl": nl, "text": body}); nl += 1; added += 1
        elif tag == "-":
            cur["lines"].append({"t": "del", "ol": ol, "nl": None, "text": body}); ol += 1; removed += 1
        else:
            cur["lines"].append({"t": "ctx", "ol": ol, "nl": nl, "text": body}); ol += 1; nl += 1
    return hunks, {"added": added, "removed": removed}


def diff_versions(file, base, compare):
    """The REDACTED structured-hunk DIFF between two revs. REDACT-THEN-DIFF (review §1.1 / design §3.2): fetch both
    blobs, redact EACH, then difflib the redacted texts — so a change confined to a secret value renders as
    `‹redacted› → ‹redacted›` context and never leaks that *a* secret changed. {available, reason, file, a_rev,
    b_rev, redacted, stats:{added,removed}, hunks:[...], note}. Validation runs before any `git show` (M2)."""
    st = store_state()
    if not st["available"]:
        return {"available": False, "reason": st["reason"], "hunks": []}
    cap = st["cap_dir"]
    _validate_rev(base)
    _validate_rev(compare)
    _validate_file(cap, file)
    a_text, a_red = redact(_git(cap, ["show", "%s:%s" % (base, file)]))
    b_text, b_red = redact(_git(cap, ["show", "%s:%s" % (compare, file)]))
    hunks, stats = _difflib_hunks(a_text.splitlines(), b_text.splitlines())
    return {"available": True, "file": file, "a_rev": base, "b_rev": compare,
            "redacted": a_red or b_red, "stats": stats, "hunks": hunks,
            "note": None if hunks else "identical at these revisions"}
