#!/usr/bin/env python3
"""Promote a staged proposal to `main` — the trusted PROMOTE half of C10 (propose-then-promote).

The deployed API/GUI runs as a STAGING network service (`KONTROLL_STAGE_PUSHES=1`): it can only push a
`proposed/<run_id>` ref to the canonical — it CANNOT advance `main`. This operator-run command fast-forwards
`main` into that proposal (**fast-forward ONLY** — it refuses a non-FF, so a proposal can never rewrite
history), then deletes the proposal. Run it on the control node against the canonical (a bare repo works —
`--repo /srv/kontroll.git`), or against a clone that has fetched the proposal. A Semaphore "approve" task
wrapping this is the in-GUI follow-on. Decision record: docs/privileged-mutation-enablement.md (SECURITY.md C10).

Run it as ROOT (`sudo`) — or as a member of the canonical's owning group (gid 1001). It advances `main` and
then deletes the staged proposal; the proposal ref is created by the container (uid 1001), so deleting it needs
write to the group-1001 canonical (the FF of `main` itself works as the repo owner, but the proposal cleanup
does not). Verified live 2026-06-15 (docs/privileged-mutation-enablement.md §5).

Usage:  sudo python3 scripts/kontroll-promote.py <run_id> --repo /srv/kontroll.git
"""
import argparse
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # so `from kontroll import gitio` resolves
from kontroll import gitio

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _would_brick_generate(run_id, repo):
    """FIX-M9 — the promote-time pin-conflict gate. Extract the PROSPECTIVE post-merge tree (`proposed/<run_id>`,
    which a fast-forward makes `main`) and run ITS OWN `gen-requirements.py --conflict-check`: resolve the unioned
    lockfile pins and report if generation would FAIL CLOSED (two conflicting `==` pins for one collection — or a
    bad `signature_policy`). Returns the message to refuse on, or None to proceed.

    Why at promote: two units each fine against today's `main` can conflict with EACH OTHER once both are active;
    only the FF moment (against the live `main`) is authoritative, so checking here means two conflicting `==` units
    can NEVER both become active and brick a LATER deploy's generate (which halts pre-image-build, far from the
    cause). Read-only: extracts to a temp dir and runs the proposal's OWN generator there (cwd==ROOT==the extract, so
    no path surgery) — it never touches the canonical or `main`. Fails OPEN on our own read error (git/tar missing,
    an unreadable/old ref): the generate-time fail-closed remains the backstop, and the gate must never itself block
    a clean promote."""
    ref = "proposed/%s" % run_id
    try:
        arc = subprocess.run(["git", "archive", "--format=tar", ref], cwd=repo or ROOT, capture_output=True)
        if arc.returncode != 0:
            return None                                  # can't read the ref here — promote_ref fails loudly if it's truly absent
        with tempfile.TemporaryDirectory(prefix="kontroll-promote-") as tmp:
            untar = subprocess.run(["tar", "-x", "-C", tmp], input=arc.stdout)
            gen = os.path.join(tmp, "scripts", "gen-requirements.py")
            if untar.returncode != 0 or not os.path.exists(gen):
                return None                              # extraction failed / an old proposal w/o the generator — nothing to check
            p = subprocess.run([sys.executable, gen, "--conflict-check"], cwd=tmp, capture_output=True, text=True)
            return None if p.returncode == 0 else (p.stderr.strip() or "generation would fail closed")
    except OSError:
        return None                                      # git/tar unavailable → fail open (backstop at generate)


def main(argv):
    ap = argparse.ArgumentParser(
        description="Promote a staged proposed/<run_id> ref to main (fast-forward only) — C10.")
    ap.add_argument("run_id", help="the proposal's run_id (the proposed/<run_id> ref the service created)")
    ap.add_argument("--repo", default=None,
                    help="the canonical (bare) or clone git dir (default: this repo root)")
    ap.add_argument("--skip-conflict-check", action="store_true",
                    help="skip the FIX-M9 pin-conflict gate (emergency override — promote a known-conflicting proposal)")
    args = ap.parse_args(argv)
    if not args.skip_conflict_check:                      # FIX-M9: refuse a promote that would brick the next generate
        msg = _would_brick_generate(args.run_id, args.repo)
        if msg:
            sys.stderr.write(
                "REFUSED: promoting proposed/%s would brick the next deploy's generate:\n  %s\n"
                "Re-pin the conflicting unit (or pass --skip-conflict-check to override).\n" % (args.run_id, msg))
            return 2
    return 0 if gitio.promote_ref(args.run_id, cwd=args.repo) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
