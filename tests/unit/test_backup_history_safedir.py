"""backup-configs.yml's capture-history raw-git MUTATORS must carry a scoped `-c safe.directory={{ config_backup_dir }}`.

WHY (the failure this guards): the capture-history store is owned by the Semaphore runtime uid (1001 — the scheduled
writer). When an operator hand-runs backup-configs.yml on the host to debug or seed a first capture, they run as a
DIFFERENT uid (root via sudo, or the uid-1000 operator — uid-1001 has no host passwd entry), so every raw-git command
against the store aborts with `fatal: detected dubious ownership`; the snapshot commit never lands and the C14 viewer
shows nothing. (Realized live during the 2026-06-24 C14 prod dogfood — the commit had to be finished by hand with
`git -c safe.directory=<store>`.) The `safe.directory=<store>` global option (scoped to the store, NEVER `*`) makes the
mutators uid-agnostic; it is a no-op on the same-uid runner path and grants no write capability. These static
assertions pin the flag onto the rm/add/commit mutators (so a refactor can't silently reintroduce the abort) and pin
the no-wildcard scoping (a `*` would trust any repo the process touches — acceptable only inside the single-tenant
runner image, never in a host-runnable play). `git init` is intentionally EXEMPT (it creates the repo, so the guard
has nothing to check). A behavioral uid-spoofing test would need root + multiple uids in CI (a layer the suite
deliberately lacks) for a one-flag change, and the failure mode is a loud abort not silent corruption — so a static
assertion is the right depth. Audit: docs/reviews/2026-06-24-deploy-codification-audit/.
"""
import os

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLAYBOOK = os.path.join(ROOT, "ansible", "playbooks", "backup-configs.yml")
SCOPED_SAFE = "safe.directory={{ config_backup_dir }}"


def _git_commands():
    """Every raw-git `command:` cmd string in backup-configs.yml, whitespace-normalized (folded scalars collapse)."""
    plays = yaml.safe_load(open(PLAYBOOK, encoding="utf-8")) or []
    out = []
    for play in plays:
        for task in (play.get("tasks") or []):
            v = task.get("ansible.builtin.command") or task.get("command")
            cmd = (v.get("cmd") if isinstance(v, dict) else v) if v is not None else None
            if isinstance(cmd, str) and cmd.strip().startswith("git "):
                out.append(" ".join(cmd.split()))
    return out


def test_history_mutators_carry_scoped_safe_directory():
    """The rm --cached / add / commit capture-history mutators each set safe.directory scoped to the store, so a
    cross-uid host hand-run doesn't abort on dubious-ownership; `git init` is exempt (it creates the repo)."""
    cmds = _git_commands()
    assert cmds, "no raw-git commands parsed from backup-configs.yml — parsing broke or the tasks moved"
    mutators = [c for c in cmds if (" rm " in c or " add " in c or " commit " in c)]
    assert len(mutators) >= 3, "expected the rm/add/commit capture-history mutators, found: %r" % mutators
    for c in mutators:
        assert SCOPED_SAFE in c, "history mutator missing scoped safe.directory (dubious-ownership footgun): %s" % c
    for c in [c for c in cmds if " init " in c]:
        assert SCOPED_SAFE not in c, "git init must not carry safe.directory (it creates the repo): %s" % c


def test_safe_directory_is_scoped_never_wildcard():
    """safe.directory must be path-scoped to config_backup_dir, NEVER `*` — the wildcard trusts any repo the process
    touches (acceptable only inside the single-tenant runner image, never in this host-runnable play)."""
    for c in _git_commands():
        assert "safe.directory=*" not in c, "safe.directory=* is too broad in a host-runnable play: %s" % c
