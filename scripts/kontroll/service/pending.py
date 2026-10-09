"""pending domain — the read-only "what proposals are awaiting promotion?" view (#129, gap 3 / C10).

`list_pending()` lists the canonical bare repo's `refs/heads/proposed/<run_id>` branches — every change STAGED by
the network service (onboard / capability / secret / keygen) that has not yet been promoted to `main`. Each entry
carries the run_id (the load-bearing field the operator copies into the Semaphore `promote-proposal` task), the
tip subject ("what it changes" at a glance), the staged-at time, the author, and the changed-path NAMES. It is a
PURE READ of the canonical (`/srv/kontroll.git` by default, or `$KONTROLL_CANONICAL_GIT`) and writes NOTHING — it
**never promotes** (promote stays the separate, admin-authed Semaphore app: C10 two-key safety; the proposer's
read surface must never be the promoter — so this module imports neither `gitio.promote_ref` nor
`commit_and_push`, and never `git push`/`update-ref`).

WHY this surface exists: the network service stages `proposed/<run_id>` refs the operator can otherwise see only
in the transient propose response (gone once the dialog closes) or via a manual `git for-each-ref` on the box.
This is the GUI answer to "where do I get the run_id to promote?" — a standing list with a one-click copy + the
exact Semaphore recipe. A missing/empty/non-git canonical → `proposals: []` + an informational note (never raises;
the in-process GUI worker must survive — service-never-sys.exit, mirroring `fleet.list_fleet`'s posture). Serves
metadata + path NAMES only — never file contents (that is the C8 backup-viewer's problem, deliberately not here).
"""
import logging
import os
import subprocess

log = logging.getLogger("kontroll.service.pending")

DEFAULT_CANONICAL = "/srv/kontroll.git"     # the in-container bind path; matches configure-semaphore's LOCAL_GIT_URL
PROMOTE_TASK = "promote-proposal"           # config/semaphore/templates/ — handed to the GUI so the pointer isn't
#                                             hard-coded twice (config-as-data: the panel renders this name).
_FE_FMT = ("%(refname:short)%09%(objectname:short)%09"
           "%(committerdate:iso8601-strict)%09%(authorname)%09%(contents:subject)")


def _canonical(canonical=None):
    """Resolve the canonical bare-repo path: explicit arg (tests) → $KONTROLL_CANONICAL_GIT → the default bind."""
    return canonical or os.environ.get("KONTROLL_CANONICAL_GIT") or DEFAULT_CANONICAL


def _git(canonical, args, timeout=5):
    """Read-only git against the canonical bare repo. argv list, NEVER shell=True; bounded timeout so a git hang
    can't wedge the in-process worker. Returns stdout (text) or None on any failure/timeout (degrade, never raise)."""
    try:
        p = subprocess.run(["git", "-C", canonical] + args,
                           capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout if p.returncode == 0 else None


def _changed_paths(canonical, ref):
    """The file NAMES this proposal touches vs main — `git diff --name-only main..<ref>` (names only, never
    contents: no C8 weight). Cheap (proposals are few + transient). [] on any failure (never blocks the list)."""
    out = _git(canonical, ["diff", "--name-only", "main..%s" % ref])
    return [ln for ln in (out or "").splitlines() if ln] if out is not None else []


def _promotable(canonical, ref):
    """Would the fast-forward-ONLY promote gate accept this proposal? True iff `main` is an ancestor of the proposal
    — the EXACT check the FF-only gate makes (`git merge-base --is-ancestor refs/heads/main <ref>`). READ-ONLY (no
    write; `merge-base --is-ancestor` is an allowed read, same verb the AST pin whitelists). Returns True (a clean
    fast-forward), False (non-FF: `main` advanced UNDER it — the FF-race — so it is stale and a fresh proposal is
    needed), or None (couldn't determine — a bad ref / git error; never badge stale on an unknown). WHY: the
    auto-promoter (or any out-of-band advance) can move `main` past an earlier-staged HIGH-blast proposal, leaving it
    non-FF; the gate then silently refuses it. Surfacing this lets the panel flag 'stale — re-propose' instead of
    listing a dead run_id as promotable."""
    try:
        p = subprocess.run(["git", "-C", canonical, "merge-base", "--is-ancestor", "refs/heads/main", ref],
                           capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode == 0:
        return True                     # main is an ancestor of the proposal → a clean fast-forward
    if p.returncode == 1:
        return False                    # not an ancestor → non-FF (main moved under it: stale)
    return None                         # 128 etc. — a git error; don't claim stale on an unknown


def _repropose_hint(paths):
    """A read-only routing hint for the GUI 'Re-propose' button on a STALE proposal (the FF-race remediation, Move
    1). Returns {"kind": "onboard", "key": <class key>} ONLY when the proposal's changed-path NAMES carry an onboard
    drop-in (`…/onboarded-<key>.yml`) — the class key is the SINGLE fact a ref's path names yield. Host/group/creds
    live INSIDE the inventory YAML, never in a path name, so they are deliberately NOT reconstructed here: the
    existing onboard dialog owns reconstruction, the human re-enters them (SOPS is irreversible; a base-moved HIGH
    proposal WANTS that re-review). Returns None for any other proposal shape (a capability/actuation/homepage/secret
    change), for which the panel keeps the plain 'stale' hint. Pure string work over the NAMES list list_pending
    already computes — no new read, no git call (so the read-only pin stays trivially green; MF-2/MF-3)."""
    for p in paths or []:
        base = p.replace("\\", "/").rsplit("/", 1)[-1]
        if base.startswith("onboarded-") and base.endswith(".yml"):
            key = base[len("onboarded-"):-len(".yml")]
            if key:
                return {"kind": "onboard", "key": key}
    return None


def list_pending(canonical=None):
    """The staged proposals awaiting promotion (C10). See the module docstring. Returns:
        {"proposals": [ {run_id, ref, sha, staged_at, author, subject, paths, promotable, repropose_hint}, ... ],
         "canonical": "<resolved path>", "promote_task": "promote-proposal", "note": None|"..."}
    Newest-first. NEVER raises; a missing/non-git/empty canonical yields proposals=[] + an informational note."""
    cdir = _canonical(canonical)
    base = {"proposals": [], "canonical": cdir, "promote_task": PROMOTE_TASK, "note": None}
    if not os.path.isdir(cdir):
        base["note"] = "canonical repo not present (no proposals on this deploy)"
        return base
    out = _git(cdir, ["for-each-ref", "--format=" + _FE_FMT, "refs/heads/proposed"])
    if out is None:
        base["note"] = "could not read the canonical (not a git dir, or git unavailable)"
        return base
    proposals = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue                                       # malformed line — skip, never half-fail
        refname, sha, staged_at, author, subject = parts[0], parts[1], parts[2], parts[3], parts[4]
        run_id = refname[len("proposed/"):] if refname.startswith("proposed/") else refname
        paths = _changed_paths(cdir, refname)
        proposals.append({"run_id": run_id, "ref": refname, "sha": sha,
                          "staged_at": staged_at, "author": author, "subject": subject,
                          "paths": paths,
                          "promotable": _promotable(cdir, refname),
                          "repropose_hint": _repropose_hint(paths)})
    proposals.sort(key=lambda p: p["staged_at"], reverse=True)       # newest first
    base["proposals"] = proposals
    if not proposals:
        base["note"] = ("no proposals pending (this deploy may commit directly to main; proposals appear only "
                        "when the staging deploy is armed)")
    return base
