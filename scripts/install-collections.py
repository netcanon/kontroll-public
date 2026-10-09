#!/usr/bin/env python3
"""The NEVER-BRICK collection install wrapper (R5 PR-B / C15-a) — now with the L2b recorded-sha256 floor.

Replaces the flat `ansible-galaxy collection install -r <lockfile>` at ansible/playbooks/bootstrap.yml with the
adaptive-signature posture AND, on the control node, the **recorded-sha256 re-verify (L2b)** that is the *entire*
substitute for the absent signature on a 0-signature fleet (docs/reviews/2026-06-25-never-brick-supply-chain/,
synthesis Decision R1; MF-1). The signature layer (L3) verifies a GPG signature WHERE the source serves one AND we
hold the key; L2b binds the whole-artifact bytes by digest where no signature is served.

Brick-proof by construction (the operator invariant: a novice is never bricked because a publisher didn't sign a
collection):
  * NO keyring on disk (today's reality — public Galaxy serves ZERO signatures for the fleet) ⇒ no L3 flags. NEVER
    a `+`-prefixed signature count (that fails on ABSENCE ⇒ would brick the unsigned fleet); the ignore-list is
    EXACTLY {NO_PUBKEY, NODATA} — never a tamper code.
  * L2b runs ONLY where the wrapper-owned trust root (`instance/trust/`) exists — the control node (I-1 bootstrap),
    where the digest lock persists across re-runs. The runner-image build (I-2) does NOT carry `instance/`, so it
    falls back to the PLAIN `-r` install (byte-identical to before; the lockfile's internal FILES.json checksum
    still applies). The gate is loud (NB-4/MF-5): a green install never implies a digest was bound when it wasn't.

The L2b flow (control node, synthesis §2 Decision R1 + report 11 §6.3, MF-2 — bind the bytes that install):
  1. Diff the lockfile against what is already installed (`collection list --format json`, LOCAL — no network), so
     a re-run with everything present does NO fetch (air-gap-safe + idempotent: no `Installing`, `0 changed`).
  2. For the to-install subset only: pre-fetch the tarballs over cert-validated HTTPS
     (`ansible-galaxy collection download`).
  3. sha256 each tarball; look it up in the gitignored, wrapper-owned lock `instance/trust/observed-digests.yml`
     keyed by exact `name==version`: a NEW key is RECORDED (first-install TOFU, R-NB-2); an existing key MISMATCH
     is **fail-closed** (a possible tarball-swap of a recorded pin — the install does NOT run); a match passes.
  4. Install from the verified local tarballs with `--offline` (so the bytes verified ARE the bytes installed —
     no re-download, no TOCTOU; MF-2).

What L2b closes (claimed exactly — synthesis §2 corollary): whole-artifact swap of an already-recorded
`name==version`. It does NOT close version-bump on a `>=` floor (a malicious newer release TOFU-records as a new
entry) — that residual (R-NB-1) is closed only by an exact `==` pin. SECURITY.md C15-a is worded to that.

Access chain used:   localhost (the control node installs its own collections)
May break:           nothing on the current fleet (unsigned ⇒ pin + checksum floor; a recorded-digest mismatch is
                     a fail-closed REFUSAL, not a brick — it means the served artifact changed under a recorded pin)
Fallback required:   no
Blast radius:        this VM only
Idempotence:         re-runnable; nothing fetched/installed when the pinned set is already present (0 changed).

Usage:  python3 scripts/install-collections.py
"""
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANSIBLE_DIR = os.path.join(ROOT, "ansible")
LOCKFILE = "collections/requirements.generated.yml"          # relative to ANSIBLE_DIR (ansible.cfg applies there)
SIDECAR = os.path.join(ANSIBLE_DIR, "collections", "trust.generated.yml")
TRUST_DIR = os.path.join(ROOT, "instance", "trust")          # the wrapper-owned trust root (present ⇒ control node)
DIGEST_LOCK = os.path.join(TRUST_DIR, "observed-digests.yml")  # gitignored, per-node TOFU state (Decision R1)

IGNORE_CODES = ("NO_PUBKEY", "NODATA")    # EXACTLY these — absence-of-trust, NOT tamper (never widen; report 20 §7.4)
# A collection artifact filename: <namespace>-<name>-<version>.tar.gz. namespace/name are `[a-z0-9_]+` (no dashes),
# so the FIRST two dash-fields are namespace+name and the remainder is the version (which may carry pre-release
# dashes). Version-independent (works regardless of the ansible-core download layout).
_ARTIFACT_RE = re.compile(r"^([a-z0-9_]+)-([a-z0-9_]+)-(.+)\.tar\.gz$")


def _sidecar():
    """The trust policy, or {} if absent/unreadable — an absent sidecar ⇒ a plain install (never-brick)."""
    try:
        with open(SIDECAR, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return {}


def build_argv(sidecar, keyring_exists, reqs=None, artifacts=None, offline=False):
    """The ansible-galaxy install argv. Plain `-r <reqs>` by default (defaults to the LOCKFILE — the plain/image
    path, byte-identical to before); the L2b path passes `artifacts=` (the pre-verified local tarball PATHS,
    installed positionally + `--offline`) so the install consumes EXACTLY the bytes the wrapper hashed — installing
    by absolute path is `cwd`-independent and bypasses the download dir's relative-source requirements file (MF-2).
    A keyring present ⇒ the adaptive never-brick signature flags (NEVER a `+`-prefixed count; ignore-list fixed at
    {NO_PUBKEY, NODATA}). Two env overrides let the SAME wrapper serve both seams (G-4): KONTROLL_GALAXY_BIN selects
    the binary, KONTROLL_COLLECTIONS_PATH adds the image's `-p` target. Bootstrap (I-1) sets neither ⇒ unchanged."""
    bin_ = os.environ.get("KONTROLL_GALAXY_BIN") or "ansible-galaxy"
    argv = [bin_, "collection", "install"]
    argv += list(artifacts) if artifacts else ["-r", reqs or LOCKFILE]  # L2b: positional tarball paths vs `-r` reqs
    coll_path = os.environ.get("KONTROLL_COLLECTIONS_PATH") or None
    if coll_path:
        argv += ["-p", coll_path]                                    # the runner-image install target (I-2)
    if offline:
        argv += ["--offline"]                                        # consume the pre-fetched, verified tarballs (L2b)
    if sidecar.get("keyring") and keyring_exists:
        argv += ["--keyring", sidecar["keyring"],
                 "--required-valid-signature-count", "all",          # pass-if-absent, fail-on-invalid (never `+`)
                 "--ignore-signature-status-codes", *IGNORE_CODES]   # absence-of-trust tolerated; tamper is NOT
    return argv


def summary(sidecar):
    """A one-line provenance summary (NB-4: degradation is loud, never silent) — collection COUNTS by policy,
    never a key or credential. A green install must not imply a signature was verified on an unsigned fleet."""
    counts = {}
    for c in sidecar.get("collections") or []:
        pol = c.get("signature_policy", "adaptive")
        counts[pol] = counts.get(pol, 0) + 1
    by = ", ".join("%s=%d" % (k, counts[k]) for k in sorted(counts)) or "none"
    return ("provenance: %d collection(s) — policy %s; verified by pin + checksum (signature where served)"
            % (sum(counts.values()), by))


# ── L2b: the recorded-sha256 floor (pure decision logic — the orchestration in main() injects the subprocess) ──────
def lockfile_entries(path=None):
    """The lockfile's pinned set → [{name, version}], or [] if absent. The {name, version} the wrapper installs and
    keys the digest lock by. PURE read (no network)."""
    try:
        with open(path or os.path.join(ANSIBLE_DIR, LOCKFILE), encoding="utf-8") as fh:
            return [c for c in (yaml.safe_load(fh) or {}).get("collections") or [] if c.get("name")]
    except (OSError, yaml.YAMLError):
        return []


def installed_versions(run, bin_):
    """{name: version} already installed, via `collection list --format json` (LOCAL — no network). {} on any
    failure (→ everything is to-install: safe, never skips a needed install). The air-gap/idempotence input: a
    present pinned set ⇒ no fetch. `run` is the subprocess seam tests inject."""
    try:
        p = run([bin_, "collection", "list", "--format", "json"], cwd=ANSIBLE_DIR,
                capture_output=True, text=True)
        if p.returncode != 0:
            return {}
        out = {}
        for _path, colls in (json.loads(p.stdout) or {}).items():
            for name, info in (colls or {}).items():
                out.setdefault(name, (info or {}).get("version"))    # first search-path wins (ansible precedence)
        return out
    except (json.JSONDecodeError, OSError, ValueError):
        return {}


def _ver_key(v):
    """A comparable tuple from a version string's leading dotted-numeric part ('4.0.0' -> (4, 0, 0)); pre-release /
    build suffixes are ignored (these are floor checks, not exact pins). A non-numeric head sorts lowest ((-1,)). PURE."""
    head = re.match(r"\d+(?:\.\d+)*", str(v or "").strip())
    return tuple(int(p) for p in head.group(0).split(".")) if head else (-1,)


def version_satisfied(installed, spec):
    """Is `installed` (a version string or None) good enough for lockfile `spec`? PURE. An `==X` spec needs an
    EXACT match (else a reinstall is owed). A `>=X` spec is a REAL floor — satisfied ONLY when installed >= X: a
    LOWER installed version does NOT satisfy it and IS to-install. This closes the fresh-Debian shadow bug — the apt
    `ansible` metapackage preseeds an old community.docker (3.4.7) into /usr/lib/.../dist-packages that
    `collection list` reports as installed; treating any floor as already-met let 3.4.7 mask the `>=4.0.0` pin so the
    deploy's `docker_image_build` (added in 3.6) went unresolved. A bare spec is satisfied by ANY installed version
    (ansible-galaxy `-r` never upgrades it). Absent is never satisfied."""
    if installed is None:
        return False
    s = str(spec or "").strip()
    if s.startswith("=="):
        return installed == s[2:].strip()
    if s.startswith(">="):
        return _ver_key(installed) >= _ver_key(s[2:].strip())       # a floor IS a constraint (dist-packages shadow fix)
    return True                                                      # bare: present-at-any-version is enough


def to_install(entries, installed):
    """The lockfile subset not already satisfied on disk → the only set the wrapper fetches + installs (PURE).
    Empty ⇒ a no-op run (no network, `0 changed`)."""
    return [e for e in entries if not version_satisfied(installed.get(e["name"]), e.get("version"))]


def parse_artifact(filename):
    """`<namespace>-<name>-<version>.tar.gz` → `"namespace.name==version"` (the digest-lock key), or None for a
    non-artifact file. PURE; version-layout-independent."""
    m = _ARTIFACT_RE.match(os.path.basename(filename))
    return ("%s.%s==%s" % (m.group(1), m.group(2), m.group(3))) if m else None


def sha256_file(path):
    """The sha256 hex digest of a file, streamed (the whole-artifact digest L2b binds). PURE read."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_digests(path=None):
    """The recorded TOFU digests `{name==version: sha256}` (or {}). The wrapper-owned, gitignored, per-node lock."""
    try:
        with open(path or DIGEST_LOCK, encoding="utf-8") as fh:
            return (yaml.safe_load(fh) or {}).get("digests") or {}
    except (OSError, yaml.YAMLError):
        return {}


def save_digests(digests, path=None):
    """Persist the TOFU lock (sorted, generated header). Writes ONLY when there is something to record."""
    target = path or DIGEST_LOCK
    os.makedirs(os.path.dirname(target), exist_ok=True)
    body = "".join('  "%s": "%s"\n' % (k, digests[k]) for k in sorted(digests))
    with open(target, "w", encoding="utf-8", newline="\n") as out:
        out.write("---\n"
                  "# GENERATED by scripts/install-collections.py (the never-brick install wrapper) — DO NOT EDIT.\n"
                  "# The sha256 of each collection tarball recorded at first install (TOFU) and re-verified on\n"
                  "# later installs; a mismatch fails the install closed. Per-node runtime state; gitignored.\n"
                  "schema: 1\n"
                  "digests:\n" + body)


def record_or_verify(digests, nv, digest):
    """TOFU one artifact against the lock (MUTATES `digests` on a first record). Returns 'recorded' (new — first
    install), 'ok' (matches the recorded digest), or 'mismatch' (differs — a possible swap of a recorded pin →
    the caller fails closed). PURE-ish (dict mutation only)."""
    prior = digests.get(nv)
    if prior is None:
        digests[nv] = digest
        return "recorded"
    return "ok" if prior == digest else "mismatch"


def l2b_root():
    """The wrapper-owned trust root if it exists (the control node), else None (the runner image → plain install).
    The loud, intentional gate: L2b binds only where its persistent lock can live."""
    return TRUST_DIR if os.path.isdir(TRUST_DIR) else None


def _write_subset_reqs(entries, path):
    """A minimal requirements.yml of just the to-install subset (the download input). PURE write."""
    doc = {"collections": [{"name": e["name"], "version": e["version"]} for e in entries]}
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        yaml.safe_dump(doc, out, default_flow_style=False, sort_keys=True)


def l2b_install(todo, sidecar, keyring_exists, run, bin_):
    """Pre-fetch → verify/record → install --offline the `todo` subset (control-node L2b). Returns the install
    return code, or a non-zero (3) WITHOUT installing on a recorded-digest mismatch (fail-closed). `run` is the
    subprocess seam tests inject. The download + list are captured (quiet); the install is NOT captured, so its
    `Installing …` stdout still reaches ansible's `changed_when` signal (FIX-IDEM)."""
    with tempfile.TemporaryDirectory(prefix="kontroll-l2b-") as dl:
        reqs = os.path.join(dl, "subset.in.yml")
        _write_subset_reqs(todo, reqs)
        dlp = run([bin_, "collection", "download", "-r", reqs, "-p", dl], cwd=ANSIBLE_DIR,
                  capture_output=True, text=True)
        if dlp.returncode != 0:                                      # a fetch failure is an availability error, not tamper
            sys.stderr.write(getattr(dlp, "stderr", "") or "")
            print("ERROR: pre-fetch failed (network/availability) — nothing installed")
            return dlp.returncode or 1
        digests = load_digests()
        changed = False
        tarballs = sorted(glob.glob(os.path.join(dl, "*.tar.gz")))   # the to-install subset + their deps
        for tarball in tarballs:
            nv = parse_artifact(tarball)
            if not nv:
                continue
            status = record_or_verify(digests, nv, sha256_file(tarball))
            if status == "mismatch":                                # a recorded pin's bytes changed under us → REFUSE
                print("REFUSED: %s sha256 mismatch vs the recorded digest — possible artifact swap of a pinned "
                      "version. Nothing installed (L2b fail-closed). Re-pin deliberately to accept a new artifact."
                      % nv)
                return 3
            changed = changed or (status == "recorded")
            print("  L2b %-9s %s" % (status, nv))
        if changed:
            save_digests(digests)
        # install the verified local tarballs BY ABSOLUTE PATH (cwd-independent; the bytes hashed are the bytes
        # installed — MF-2) + --offline so deps resolve from the same verified set, never a re-fetch.
        argv = build_argv(sidecar, keyring_exists, artifacts=tarballs, offline=True)
        return run(argv, cwd=ANSIBLE_DIR).returncode                # not captured ⇒ 'Installing' reaches galaxy.stdout


def main(run=None):
    run = run or subprocess.run                                     # resolved at CALL time (monkeypatch-friendly)
    sidecar = _sidecar()
    keyring = sidecar.get("keyring")
    keyring_exists = bool(keyring) and os.path.exists(os.path.join(ROOT, keyring))
    bin_ = os.environ.get("KONTROLL_GALAXY_BIN") or "ansible-galaxy"
    print(summary(sidecar))
    if keyring and not keyring_exists:
        print("note: keyring %s not present — installing on the pin + checksum floor (unsigned source)" % keyring)

    if l2b_root() is None:                                           # runner image / no trust root ⇒ plain install
        print("L2b digest re-verify: NOT engaged (no instance/trust) — pin + checksum floor only")
        argv = build_argv(sidecar, keyring_exists)
        sys.exit(run(argv, cwd=ANSIBLE_DIR).returncode)             # tamper (a failed signature) ⇒ non-zero ⇒ fail closed

    entries = lockfile_entries()
    todo = to_install(entries, installed_versions(run, bin_))
    print("L2b digest re-verify: engaged (lock %s) — %d/%d collection(s) to install"
          % (os.path.relpath(DIGEST_LOCK, ROOT), len(todo), len(entries)))
    if not todo:
        print("L2b: the pinned set is already present — nothing to fetch or install")
        sys.exit(0)                                                 # idempotent + air-gap-safe; no 'Installing'
    sys.exit(l2b_install(todo, sidecar, keyring_exists, run, bin_))


if __name__ == "__main__":
    main()
