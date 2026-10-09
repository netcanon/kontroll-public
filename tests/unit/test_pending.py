"""pending — the read-only "proposals awaiting promotion" view (#129, gap 3 / C10).

These pin service/pending.py: list_pending() is a PURE read of the canonical bare repo's refs/heads/proposed/*
branches into {run_id, ref, sha, staged_at, author, subject, paths}, newest-first, with the run_id stripped from
the ref name (the value the operator pastes into the Semaphore promote-proposal survey). WHY (the gap this fills):
before this a staged proposal's run_id was visible only in the transient propose response — the operator had no
standing list to promote from. They also pin the C10 read-only guarantee: the lister NEVER promotes (no
promote/push path) — the proposer's read surface must not be the promoter.
"""
import ast
import inspect
import os
import subprocess

import pytest

from _readonly_pins import assert_read_only
from kontroll.service import pending

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd)] + list(args), check=True, capture_output=True, text=True)


@pytest.fixture
def bare_with_proposals(tmp_path):
    """A throwaway CANONICAL: a bare repo with `main` + two proposed/<run_id> refs, each a 1-commit FF over main
    touching a file — so list_pending sees two proposals + their changed paths. A local filesystem path is used as
    the push target (cross-platform; no file:// URL). Returns the bare path."""
    bare = tmp_path / "canonical.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(bare)], check=True, capture_output=True)
    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "-b", "main")
    _git(work, "config", "user.email", "t@t")
    _git(work, "config", "user.name", "t")
    (work / "seed.txt").write_text("base\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "base")
    _git(work, "push", str(bare), "HEAD:refs/heads/main")
    for rid, path in (("abc123def456", "modules/foo/module.yml"), ("def456abc789", "ansible/inventory/foo.yml")):
        (work / "p.txt").write_text(rid + "\n", encoding="utf-8")
        _git(work, "add", "-A")
        _git(work, "commit", "-m", "feat(onboard): stage %s (run_id %s)" % (path, rid))
        _git(work, "push", str(bare), "HEAD:refs/heads/proposed/%s" % rid)
        _git(work, "reset", "--hard", "HEAD~1")                  # next proposal branches off main again
    return bare


def test_lists_proposals_with_runid_and_metadata(bare_with_proposals):
    """Each proposed/<run_id> ref appears once with the run_id STRIPPED from the ref, plus sha/staged_at/subject;
    the run_id is exactly the string the Semaphore promote-proposal survey expects. Guards the parse of the one
    for-each-ref call the panel relies on (a wrong parse would feed the operator an un-promotable id)."""
    out = pending.list_pending(canonical=str(bare_with_proposals))
    ids = {p["run_id"] for p in out["proposals"]}
    assert ids == {"abc123def456", "def456abc789"}
    p = next(x for x in out["proposals"] if x["run_id"] == "abc123def456")
    assert p["ref"] == "proposed/abc123def456" and p["sha"] and p["staged_at"]
    assert "feat(onboard)" in p["subject"]
    assert out["promote_task"] == "promote-proposal"


def test_proposal_reports_its_changed_paths(bare_with_proposals):
    """Each proposal carries its changed-file NAMES (diff --name-only main..ref) — the read-only "what it changes"
    detail the row shows: the metadata analogue of a diff WITHOUT serving file contents (no C8 weight). Guards the
    changes-summary against drifting from the actual ref."""
    out = pending.list_pending(canonical=str(bare_with_proposals))
    assert all(isinstance(p["paths"], list) for p in out["proposals"])
    assert any(p["paths"] for p in out["proposals"])            # the proposals touch a file
    # Every proposal carries the read-only re-propose hint field (None here — the fixture proposals aren't onboards);
    # pins the field's PRESENCE so the GUI can always read p.repropose_hint without a per-row existence check (Move 1).
    assert all("repropose_hint" in p for p in out["proposals"])
    assert all(p["repropose_hint"] is None for p in out["proposals"])


def test_repropose_hint_derives_the_class_from_an_onboard_dropin():
    """FF-race Move 1: `_repropose_hint` yields {kind:onboard, key} ONLY from an `onboarded-<key>.yml` path NAME —
    the single fact a ref's path names carry — and None for any non-onboard proposal shape. Guards the MF-2 boundary:
    the read view derives the CLASS to route the re-propose button, and NEVER reconstructs host/group/creds (those
    live inside the inventory YAML, not in a path name; the onboard dialog + the human own them). A drift that let a
    capability/homepage/secret proposal masquerade as an onboard — or that started parsing YAML for host/group —
    would fail here."""
    hint = pending._repropose_hint(["instance/inventory/onboarded-cisco_ios.yml", "modules/cisco_ios/module.yml",
                                     "config/fleet.yml"])
    assert hint == {"kind": "onboard", "key": "cisco_ios"}
    # a backslash path (a Windows-style name in the diff) still yields the leaf key
    assert pending._repropose_hint(["ansible\\inventory\\onboarded-arista_eos.yml"]) == {"kind": "onboard",
                                                                                          "key": "arista_eos"}
    # non-onboard shapes → None (the panel keeps the plain 'stale' prose, no button)
    assert pending._repropose_hint(["modules/foo/module.yml", "config/fleet.yml"]) is None   # capability-only
    assert pending._repropose_hint(["gui/homepage/overlay.yml"]) is None                     # homepage edit
    assert pending._repropose_hint(["onboarded-.yml"]) is None                               # empty key ⇒ no hint
    assert pending._repropose_hint([]) is None and pending._repropose_hint(None) is None


def test_promotable_flag_distinguishes_ff_from_stale(tmp_path):
    """`promotable` surfaces the fast-forward-only promote gate's verdict read-only: a proposal that is a clean FF of
    `main` reports True; one that `main` has advanced PAST (non-FF) reports False. Guards the exact FF-race the live
    Cisco dogfood hit — an earlier HIGH-blast proposal stranded when a later LOW-blast one promoted; the panel must
    badge it 'stale — re-propose' rather than list a dead run_id as promotable (which would refuse on promote)."""
    bare = tmp_path / "c.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(bare)], check=True, capture_output=True)
    work = tmp_path / "w"
    work.mkdir()
    _git(work, "init", "-b", "main")
    _git(work, "config", "user.email", "t@t")
    _git(work, "config", "user.name", "t")
    (work / "seed.txt").write_text("base\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "base")
    _git(work, "push", str(bare), "HEAD:refs/heads/main")                     # main @ base
    # a STALE proposal: staged off base, BEFORE main advances
    (work / "stale.txt").write_text("y\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "feat: stale one")
    _git(work, "push", str(bare), "HEAD:refs/heads/proposed/57a1e0000000")
    _git(work, "reset", "--hard", "HEAD~1")                                   # back to base
    # advance main PAST the stale proposal (the FF race)
    (work / "adv.txt").write_text("z\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "advance main")
    _git(work, "push", str(bare), "HEAD:refs/heads/main")                     # main @ base+adv (work HEAD here)
    # a FF proposal: staged off CURRENT main
    (work / "ff.txt").write_text("x\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "feat: ff one")
    _git(work, "push", str(bare), "HEAD:refs/heads/proposed/ff0000000000")
    by = {p["run_id"]: p for p in pending.list_pending(canonical=str(bare))["proposals"]}
    assert by["ff0000000000"]["promotable"] is True          # a clean fast-forward of current main
    assert by["57a1e0000000"]["promotable"] is False         # main advanced past it → non-FF (stale)


def test_empty_and_absent_canonical_degrade_never_raise(tmp_path):
    """An empty canonical (a bare repo with no proposed/* refs) → proposals == [] + an informational note; an
    absent path → likewise [] + a note (never an exception, never a crash). Guards the service-never-sys.exit /
    degrade-gracefully posture: a fresh/unarmed deploy shows an honest empty state, not a 500."""
    bare = tmp_path / "empty.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(bare)], check=True, capture_output=True)
    empty = pending.list_pending(canonical=str(bare))
    assert empty["proposals"] == [] and empty["note"]
    absent = pending.list_pending(canonical=str(tmp_path / "does-not-exist"))
    assert absent["proposals"] == [] and absent["note"]


def test_pending_is_read_only_by_construction():
    """C10 two-key: the Pending lister must NEVER gain a promote/push affordance — the proposer's read surface is
    not the promoter. The AST pin (#133) asserts list_pending calls no write/actuation verb; an additional source
    grep asserts pending.py names no git-write subcommand (a `git push`/`update-ref` would slip past a call-name
    check since it rides a subprocess arg list). Guards a future edit quietly adding a 'promote from the GUI' path
    that would collapse the propose→promote split."""
    assert_read_only("scripts/kontroll/service/pending.py", "list_pending")
    # Grep the EXECUTABLE code (docstring stripped — it legitimately names the forbidden helpers to document the
    # C10 contract). ast.unparse drops the module docstring + comments, leaving code + string/identifier literals.
    tree = ast.parse(inspect.getsource(pending))
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
        tree.body = tree.body[1:]                              # drop the module docstring node
    code = ast.unparse(tree)
    for forbidden in ("promote_ref", "commit_and_push", "update-ref", '"push"', "'push'"):
        assert forbidden not in code, "pending.py must not reference a git-write path in code: %s" % forbidden


def test_template_wires_the_pending_panel():
    """The header exposes a `pending-open` button → `openPendingPanel()` which fetches `/api/pending` and renders
    `pending-row`s with a `pending-copy-runid` affordance + a static `pending-promote-hint` (NEVER a promote
    trigger). Pins the GUI round-trip + the C10 no-promote-button property at the template level (testids recorded
    in testid_reference.md)."""
    tpl = open(os.path.join(ROOT, "gui", "templates", "index.html"), encoding="utf-8").read()
    assert 'data-testid="pending-open"' in tpl and "openPendingPanel()" in tpl and "/api/pending" in tpl
    assert "'pending-row'" in tpl and "'pending-copy-runid'" in tpl and "'pending-promote-hint'" in tpl
    assert "cannot promote" in tpl                              # the hint states the GUI cannot promote (C10)
    # the FF-race surface: a non-FF proposal is badged 'stale — re-propose' + gets a re-propose hint (not the recipe)
    assert "'pending-stale'" in tpl and "'pending-stale-hint'" in tpl and "p.promotable === false" in tpl
    # FF-race Move 1: a stale onboard proposal (repropose_hint) gets a `pending-re-propose` button that navigates to
    # the class's onboard dialog (reproposeFromPending → search). It is gated on stale + a hint, and NEVER promotes.
    assert "'pending-re-propose'" in tpl and "function reproposeFromPending" in tpl
    assert "stale && p.repropose_hint" in tpl                   # button only on a stale proposal that HAS a hint
    assert "reproposeFromPending" in tpl and "promote_ref" not in tpl and "/api/promote" not in tpl   # no promote path
    # FF-race Move 2: a stale row gets a Discard button (stale-only) + a two-step confirm → discardProposal POSTs to
    # the discard route. Un-stage is not promote — no promote path in the discard flow.
    assert "'pending-discard'" in tpl and "'pending-discard-confirm'" in tpl and "'pending-discard-error'" in tpl
    assert "'pending-discard-cancel'" in tpl                    # the confirm escape hatch (grep-verified; e2e-exercised)
    assert "function discardProposal" in tpl and "/discard'" in tpl and "method: 'POST'" in tpl
    assert "if (stale) {" in tpl                                # the discard control is gated on stale
