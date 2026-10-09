"""discard domain — delete a STALE staged proposal from the canonical (FF-race remediation, Move 2 / C10).

`discard_proposal(run_id, canonical)` removes a `refs/heads/proposed/<run_id>` ref from the canonical bare repo —
the ONE write verb in the pending surface, kept in its OWN module so `pending.py` stays strictly read-only (the
lister must never be the reaper). It is C10-SAFE by construction: un-staging a proposal removes Key-1's OWN output
— it CANNOT advance `main`, enact anything, or grow the promotable set (unlike promote, which is the separate,
admin-authed Semaphore app). WHY it exists: the auto-promoter (or any out-of-band advance) can leave earlier-staged
proposals non-fast-forwardable (the FF-race). Part 1 badges them "stale"; Move 1 offers re-propose; this reaps the
dead refs re-propose leaves behind so the Pending list doesn't accrete un-promotable cruft.

SECURITY (the design-of-record's must-fixes, folded in — docs/reviews/2026-07-05-ff-race-parked-proposals/):
  - SEC-B1: the run_id validator accepts BOTH real minter shapes anchored (`uuid4().hex[:12]` = 12 hex; the API's
    `mint_run_id` = `YYYYMMDDTHHMMSSZ-<6hex>`) and NOTHING else — so `/`, whitespace, `..`, a leading `-`, or `main`
    can never reach git. Structurally, the ref is built (`refs/heads/proposed/<rid>`) and passed AFTER
    `--end-of-options`, so even a hypothetical leading-`-` leaf can never be read as a flag (defence in depth with
    the regex).
  - SEC-M1/m2: COMPARE-AND-DELETE. The tip sha is read first and the delete is `git update-ref -d <ref> <oldsha>` —
    it deletes ONLY if `<ref>` STILL points at `<oldsha>`, closing the read-then-delete TOCTOU: a concurrent
    promote/rebase that moved or removed the ref makes the delete a no-op (a 409 to the caller), never a blind
    delete. The load-bearing SEC-m2 defense is PROVENANCE — the oldsha comes from git's own tip read and is passed
    as update-ref's oldvalue operand; as defence-in-depth it is also validated (not asserted — this module never
    raises) to be a non-zero 40/64-hex string before it reaches git (a null OID would delete UNCONDITIONALLY).
  - MF-4: the delete argv is a SINGLE literal list (`["git", …, "update-ref", "-d", …, ref, sha]`), NOT a
    `[...] + [...]` concat — so the fail-closed read-only completeness gate (`_static_list_prefix`, which reads only
    a BinOp's LEFT operand) SEES `update-ref` and forces `discard_proposal` to be registered in `WRITE_VERBS`.

NEVER raises for the caller's benefit: a bad run_id / missing canonical / vanished ref returns a structured
`{"ok": False, "error", "code"}` the route maps to 400/404/409 (never a 500).
"""
import os
import re
import subprocess

from kontroll.service.pending import DEFAULT_CANONICAL   # the SAME canonical bind pending.py reads (no drift)

# SEC-B1 — the ONLY two run_id shapes the fleet mints. `uuid4().hex[:12]` (the GUI) is 12 lowercase hex;
# `api.audit.mint_run_id` is a UTC stamp `YYYYMMDDTHHMMSSZ` + `-` + 6 hex. Anything else (a git flag, a path
# traversal, `main`) is refused before a ref is ever built. Matched with re.fullmatch (NOT `^…$` + re.match — Python's
# `$` matches before a trailing `\n`, so `^…$`.match would let `<id>\n` slip through, the codebase-wide trailing-`\n`
# trap; secrets.py/_validate.py use `\A…\Z`/fullmatch for the same reason). Pinned to BOTH minters in test_discard.
_RUNID_GUI = re.compile(r"[0-9a-f]{12}")
_RUNID_API = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}")
_SHA_RE = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")          # a 40-hex (sha1) or 64-hex (sha256) object name


def _canonical(canonical=None):
    """Resolve the canonical bare-repo path: explicit arg (tests) -> $KONTROLL_CANONICAL_GIT -> the default bind
    (mirrors pending._canonical so the reaper and the lister always target the same repo)."""
    return canonical or os.environ.get("KONTROLL_CANONICAL_GIT") or DEFAULT_CANONICAL


def _valid_run_id(run_id):
    """True iff run_id is one of the two real minter shapes (SEC-B1). Refuses everything else — a git option
    (`-d`, `--all`), a path traversal (`../main`), whitespace, or a branch name (`main`) — so a discard can only
    ever name a `proposed/<run_id>` ref the service itself minted."""
    return isinstance(run_id, str) and bool(_RUNID_GUI.fullmatch(run_id) or _RUNID_API.fullmatch(run_id))


def _current_sha(cdir, ref):
    """The tip object-name of `ref` (read-only `git show-ref --verify --hash`), or None if the ref does not exist.
    `--end-of-options` guards the ref token; the result is shape-validated (40/64-hex) AND asserted non-zero, so a
    null OID can never flow into the compare-and-delete (SEC-m2)."""
    try:
        p = subprocess.run(["git", "-C", cdir, "show-ref", "--verify", "--hash", "--end-of-options", ref],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    sha = (p.stdout or "").strip()
    if p.returncode != 0 or not _SHA_RE.fullmatch(sha) or set(sha) == {"0"}:
        return None
    return sha


def discard_proposal(run_id, canonical=None):
    """Delete the staged `proposed/<run_id>` ref from the canonical, compare-and-delete on its current tip. Returns
    a structured result (never raises):
        {"ok": True,  "run_id", "ref": "proposed/<run_id>", "sha": <deleted tip>}
        {"ok": False, "error": "<why>", "code": 400|404|409, "run_id"}
    400 = invalid run_id (SEC-B1); 404 = no canonical / no such proposal (already promoted/discarded/never staged);
    409 = the ref moved or vanished between the read and the delete (TOCTOU — refresh and retry). C10-safe: this
    removes a `proposed/*` ref only; it never advances main, enacts, or promotes."""
    if not _valid_run_id(run_id):
        return {"ok": False, "error": "invalid run_id", "code": 400, "run_id": run_id}
    cdir = _canonical(canonical)
    if not os.path.isdir(cdir):
        return {"ok": False, "error": "canonical repo not present (no proposals on this deploy)",
                "code": 404, "run_id": run_id}
    ref = "refs/heads/proposed/%s" % run_id
    sha = _current_sha(cdir, ref)                            # compare-and-delete: capture the exact tip first
    if sha is None:
        return {"ok": False, "error": "no such proposal (already promoted, discarded, or never staged)",
                "code": 404, "run_id": run_id}
    # MF-4: a SINGLE literal argv so the completeness gate sees `update-ref` and requires this verb be registered.
    # SEC-M1: `-d <ref> <oldsha>` deletes ONLY if ref still points at oldsha (a moved/removed ref -> rc!=0 -> 409).
    try:
        rc = subprocess.run(["git", "-C", cdir, "update-ref", "-d", "--end-of-options", ref, sha],
                            capture_output=True, text=True, timeout=5).returncode
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "error": "discard failed (git unavailable)", "code": 409, "run_id": run_id}
    if rc != 0:
        return {"ok": False, "error": "the proposal moved or vanished since it was listed — refresh and retry",
                "code": 409, "run_id": run_id}
    return {"ok": True, "run_id": run_id, "ref": "proposed/%s" % run_id, "sha": sha}
