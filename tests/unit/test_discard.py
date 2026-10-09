"""discard — the ONE write verb in the pending surface: delete a STALE proposal's ref (FF-race Move 2 / C10).

These pin `service/discard.discard_proposal`, the reaper for the FF-race: a proposal `main` advanced past is
non-fast-forwardable and can never be promoted, so it lingers as dead weight in the Pending list. discard removes
its `refs/heads/proposed/<run_id>` ref from the canonical. It is C10-SAFE (un-stage != promote: it deletes Key-1's
OWN output; it cannot advance main / enact / grow the promotable set) — so it lives OUTSIDE the read-only pending.py
in its own module, registered in WRITE_VERBS. The security-critical surface is the run_id → git argv path; these
tests are the design-of-record's must-fixes made executable (SEC-B1 both-minter validator + argv-injection refusal,
SEC-M1 compare-and-delete, MF-4 single-literal argv → the completeness gate sees the verb).
"""
import ast
import inspect
import os
import re
import subprocess

import pytest

from _readonly_pins import WRITE_VERBS, assert_write_verbs_complete
from api.audit import mint_run_id           # SEC-B1: pin the validator to the REAL API minter shape
from kontroll.service import discard

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd)] + list(args), check=True, capture_output=True, text=True)


@pytest.fixture
def bare_with_proposal(tmp_path):
    """A throwaway CANONICAL bare repo with `main` + one `proposed/<run_id>` ref (a 1-commit FF over main). Returns
    (bare_path, run_id) so a test can discard it and assert the ref is gone. A local filesystem path is the push
    target (cross-platform; no file:// URL)."""
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
    run_id = "abc123def456"
    (work / "p.txt").write_text("x\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", "feat(onboard): stage a proposal")
    _git(work, "push", str(bare), "HEAD:refs/heads/proposed/%s" % run_id)
    return bare, run_id


def _ref_exists(bare, run_id):
    p = subprocess.run(["git", "-C", str(bare), "show-ref", "--verify", "--quiet",
                        "refs/heads/proposed/%s" % run_id], capture_output=True)
    return p.returncode == 0


def test_discards_a_staged_proposal(bare_with_proposal):
    """The happy path: discard_proposal deletes the `proposed/<run_id>` ref and returns {ok, run_id, ref, sha}; the
    ref no longer resolves in the canonical afterward. Guards the core reaper against silently no-op'ing (a promoted
    or lingering stale proposal must actually leave the list)."""
    bare, run_id = bare_with_proposal
    assert _ref_exists(bare, run_id)
    out = discard.discard_proposal(run_id, canonical=str(bare))
    assert out["ok"] is True and out["run_id"] == run_id and out["ref"] == "proposed/%s" % run_id
    assert re.match(r"^[0-9a-f]{40}", out["sha"])              # the deleted tip, echoed for audited recovery
    assert not _ref_exists(bare, run_id)                      # actually gone from the canonical


def test_run_id_validator_accepts_both_minters_and_refuses_injection():
    """SEC-B1: `_valid_run_id` accepts EXACTLY the two shapes the fleet mints — the GUI `uuid4().hex[:12]` (12 hex)
    and the API `mint_run_id` (`YYYYMMDDTHHMMSSZ-<6hex>`) — and refuses everything else: a git flag (`-d`,`--all`),
    a path traversal (`../main`), whitespace, a branch name (`main`), the empty string, None, and a run_id with a
    `/`. Pinned to the LIVE `mint_run_id` so a future change to the API minter's alphabet breaks CI HERE (not silently
    at a live discard). This is the load-bearing guard: only a validated id ever becomes a `proposed/<id>` ref."""
    assert discard._valid_run_id("abc123def456")              # GUI uuid4().hex[:12]
    assert discard._valid_run_id(mint_run_id())               # API stamp — the real minter, not a hand-typed twin
    assert discard._valid_run_id("0" * 12)                    # boundary: all-hex, 12 chars
    for bad in ("-d", "--all", "-z", "../main", "main", "proposed/x", "a b", "abc123def45", "abc123def4567",
                "ABC123DEF456", "", "  ", "20260705T101112Z-xyz", None, 12,
                # INJ-1: a trailing/embedded newline/CR/tab must NOT slip through — Python's `$` matches before a
                # final `\n`, so `^…$`.match WOULD have let these pass; re.fullmatch is anchored strictly. Reachable
                # over HTTP as `POST /api/pending/<id>%0A/discard` (Flask decodes %0A to a real newline).
                "abc123def456\n", "abc123def456\r", "abc123def456\t", "20260705T101112Z-abcdef\n",
                "abc123\ndef456", " abc123def456"):
        assert not discard._valid_run_id(bad), "must refuse %r" % (bad,)


def test_invalid_run_id_is_400_before_any_git(bare_with_proposal):
    """An invalid run_id returns code 400 and NEVER reaches git — the proposal ref is untouched. Guards the argv
    boundary: a `-d`/`../main` can't slip through to `git update-ref` even if the canonical exists."""
    bare, run_id = bare_with_proposal
    out = discard.discard_proposal("../main", canonical=str(bare))
    assert out["ok"] is False and out["code"] == 400
    assert _ref_exists(bare, run_id)                          # the real proposal is untouched


def test_nonexistent_proposal_is_404(bare_with_proposal):
    """A valid-SHAPED run_id that names no ref → code 404 (already promoted/discarded/never staged), not a 500 and
    not a false success. Guards the compare-and-delete's read leg: no ref → nothing to delete."""
    bare, _ = bare_with_proposal
    out = discard.discard_proposal("ffffffffffff", canonical=str(bare))
    assert out["ok"] is False and out["code"] == 404


def test_missing_canonical_is_404(tmp_path):
    """An absent canonical path → code 404 (never raises). Guards the degrade posture on an unarmed deploy."""
    out = discard.discard_proposal("abc123def456", canonical=str(tmp_path / "does-not-exist"))
    assert out["ok"] is False and out["code"] == 404


def test_compare_and_delete_guards_a_concurrently_moved_ref(bare_with_proposal, monkeypatch):
    """SEC-M1/TOCTOU: the delete is conditional on the tip read first. If the ref MOVES between the read and the
    delete (a concurrent promote/rebase), `git update-ref -d <ref> <stalesha>` refuses → code 409, and the ref is
    LEFT intact (never blind-deleted). Simulated by making `_current_sha` return a stale (wrong) sha so the compare
    fails — proving the oldsha guard is actually load-bearing, not decorative."""
    bare, run_id = bare_with_proposal
    monkeypatch.setattr(discard, "_current_sha", lambda cdir, ref: "0" * 39 + "1")   # a plausible-but-wrong tip
    out = discard.discard_proposal(run_id, canonical=str(bare))
    assert out["ok"] is False and out["code"] == 409
    assert _ref_exists(bare, run_id)                          # the guard refused — ref preserved


def test_delete_argv_is_a_single_literal_with_the_oldsha(monkeypatch):
    """MF-4 + SEC-M1 (STRUCTURAL): the `git update-ref -d` call in discard.py is a SINGLE list literal (never a
    `[...] + [...]` concat) so the completeness gate's `_static_list_prefix` sees `update-ref`; and it carries both
    `-d` and the run-of-the-mill positional oldsha (compare-and-delete, not an unconditional delete). Parsed from the
    AST so a refactor that split the argv — hiding the verb from the pin or dropping the oldsha — fails HERE."""
    src = inspect.getsource(discard.discard_proposal)
    tree = ast.parse(src)
    update_ref_lists = []
    for node in ast.walk(tree):
        if isinstance(node, ast.List):
            consts = [e.value for e in node.elts if isinstance(e, ast.Constant)]
            if "update-ref" in consts:
                update_ref_lists.append((node, consts))
    assert update_ref_lists, "no `update-ref` list literal found in discard_proposal"
    node, consts = update_ref_lists[0]
    assert consts[0] == "git" and "-d" in consts and "--end-of-options" in consts   # git + delete + injection stop
    # the LAST two argv slots are the compare-and-delete operands (<ref>, <oldsha>) — variables, not constants; and
    # `--end-of-options` sits immediately before them so a leading-`-` leaf can never be parsed as a flag.
    assert isinstance(node.elts[-1], ast.Name) and isinstance(node.elts[-2], ast.Name), \
        "expected the ref + oldsha as the two trailing variable operands (compare-and-delete)"
    assert isinstance(node.elts[-3], ast.Constant) and node.elts[-3].value == "--end-of-options"


def test_discard_proposal_is_registered_and_the_completeness_gate_enforces_it(monkeypatch):
    """The read-only pin: `discard_proposal` is in WRITE_VERBS (so a read view that ever calls it trips
    assert_read_only), AND the fail-closed completeness gate would NAME it if it were unregistered — proving MF-4's
    single-literal argv makes the `update-ref` write visible to the detector (P0b/#134). Un-register it in a copy and
    assert the gate fails pointing at discard.py:discard_proposal."""
    assert "discard_proposal" in WRITE_VERBS
    import _readonly_pins as rp
    monkeypatch.setattr(rp, "WRITE_VERBS", WRITE_VERBS - {"discard_proposal"})
    with pytest.raises(AssertionError) as ei:
        assert_write_verbs_complete()
    assert "discard.py:discard_proposal" in str(ei.value)      # the gate names the exact unregistered writer
