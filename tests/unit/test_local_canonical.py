"""local-canonical.yml: the C10 canonical's gid-1001 write-grant must provision the group + the operator's
membership + operator OWNERSHIP — not just the group.

WHY (the failure this guards — hit LIVE during the #119 prod cutover, "F-CANON"): the canonical
`/srv/kontroll.git` is group-1001 (the runtime uid:gid the privileged API/runner writes as), but a FRESH
control node has no NAMED group at gid 1001 and the operator is not a member of it. The Mirror push at the end
of local-canonical.yml runs AS THE OPERATOR (no become); the moment a canonical object is group-1001-owned but
not operator-owned, that push dies with "Permission denied: unable to write objects" and the whole deploy fails.
The #119 box needed a manual `groupadd -g 1001 kontroll; usermod -aG 1001 admin; chown -R admin:1001 <canonical>`.

The fix lands those three as idempotent tasks: (1) ensure the gid-1001 group, (2) add the operator to it, and
(3) the grant on existing objects sets owner=operator too (not just group) — as detect-then-fix `find` commands that
PRUNE `hooks/`, which stays root:root 0755 so the uid-1001 writer can never plant a hook (finding 2). The owner half is load-bearing: a freshly
added supplementary group is NOT effective in the operator's current login session, so on the very first run the
push can't rely on membership yet — operator OWNERSHIP makes it succeed via OWNER perms regardless. This test
pins all three, plus the ordering (group/membership before the operator's push), so a refactor that drops any
half silently re-breaks a fresh install's first deploy.
"""
import os

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLAYBOOK = os.path.join(ROOT, "ansible", "playbooks", "local-canonical.yml")


def _tasks():
    plays = yaml.safe_load(open(PLAYBOOK, encoding="utf-8"))
    out = []
    for play in plays if isinstance(plays, list) else []:
        if isinstance(play, dict):
            out += list(play.get("tasks") or [])
    return out


def _mod(task, *keys):
    """Return the first present module dict among keys (e.g. 'ansible.builtin.group','group')."""
    for k in keys:
        v = task.get(k)
        if isinstance(v, dict):
            return v
    return None


def test_group_gid_1001_is_created():
    """A `group` task creates the gid-1001 group with become — without a named group at 1001 the canonical's
    group assignment has no member the operator can join. Guards the first half of the F-CANON manual fix."""
    hits = [t for t in _tasks() if _mod(t, "ansible.builtin.group", "group")]
    assert hits, "no group task in local-canonical.yml — the gid-1001 group is not provisioned"
    g = _mod(hits[0], "ansible.builtin.group", "group")
    assert str(g.get("gid")) == "1001", "the provisioned group must be gid 1001 (the runtime uid:gid)"
    assert hits[0].get("become") is True, "creating a system group needs become"


def test_operator_is_added_to_gid_1001_group():
    """A `user` task appends the operator to the gid-1001 group (append=true, become) so its `git push local`
    can write the group-1001 canonical. Guards the second half of the F-CANON manual fix (`usermod -aG`)."""
    hits = [t for t in _tasks() if _mod(t, "ansible.builtin.user", "user")]
    assert hits, "no user task — the operator is never added to the gid-1001 group"
    u = _mod(hits[0], "ansible.builtin.user", "user")
    assert "1001" in str(u.get("groups")) or "kontroll" in str(u.get("groups")), \
        "the user task must add the operator to the gid-1001 (kontroll) group"
    assert u.get("append") is True, "must append (supplementary) — never replace the operator's primary group"
    assert hits[0].get("become") is True, "modifying a user's groups needs become"


def _cmd(task):
    """The command/shell text of a task, whichever spelling and shape (dict with cmd, or a bare string)."""
    for k in ("ansible.builtin.command", "command", "ansible.builtin.shell", "shell"):
        v = task.get(k)
        if isinstance(v, dict):
            return str(v.get("cmd", v.get("_raw_params", "")))
        if isinstance(v, str):
            return v
    return ""


def test_the_ownership_grant_sets_operator_owner_and_prunes_hooks():
    """The write-grant on EXISTING objects (become) must set BOTH owner=operator AND group=1001 — the owner half is
    what lets the operator's first-run push succeed before the just-added group membership becomes effective (next
    login) — and it must PRUNE hooks/ so the hook files never become operator- or group-owned. It is a detect-then-fix
    pair of `find` commands now (the `file` module cannot exclude a subtree), so a second run reports 0 changed.
    Guards a regression to group-only (re-breaks F-CANON) or to a blanket recurse that re-grants hooks/."""
    chowns = [t for t in _tasks() if "chown" in _cmd(t)]
    assert len(chowns) == 1, "exactly one chown grant task: %r" % [t.get("name") for t in chowns]
    cmd = _cmd(chowns[0])
    assert "{{ operator_uid }}:1001" in cmd, "owner=operator AND group=1001 (the F-CANON owner half)"
    assert "-path {{ bare }}/hooks -prune" in cmd, "hooks/ must be pruned from the ownership grant"
    assert chowns[0].get("become") is True and chowns[0].get("when"), "become, and gated on the detector"
    blanket = [t for t in _tasks() if (m := _mod(t, "ansible.builtin.file", "file")) and m.get("recurse")
               and str(m.get("path")) == "{{ bare }}"]
    assert blanket == [], "no blanket recurse over the whole canonical — it would re-grant hooks/ every run"


def test_hooks_stay_root_owned_and_outside_every_grant():
    """hooks/ is root:root 0755 (recurse) and PRUNED from every chmod/chown grant, and the re-own task runs AFTER the
    grants. The canonical is mounted :rw into the uid-1001 service (api_privileged); with a group-writable hooks/
    that writer could plant a `reference-transaction` or `update` hook that the next `sudo kontroll-promote` runs as
    ROOT (2026-10-08 review, finding 2). Every git actor only needs to READ hooks. Guards the grant growing back over
    hooks/, the re-own going missing, or it running before a grant that would undo it."""
    tasks = _tasks()
    grants = [i for i, t in enumerate(tasks)
              if ("chmod" in _cmd(t) or "chown" in _cmd(t)) and "{{ bare }}" in _cmd(t)]
    assert grants, "the grant tasks must exist"
    for i in grants:
        assert "-path {{ bare }}/hooks -prune" in _cmd(tasks[i]), "a grant reaches into hooks/: %s" % tasks[i].get("name")
    hooks = [i for i, t in enumerate(tasks)
             if (m := _mod(t, "ansible.builtin.file", "file")) and str(m.get("path")) == "{{ bare }}/hooks"]
    assert len(hooks) == 1, "exactly one task owns hooks/"
    m = _mod(tasks[hooks[0]], "ansible.builtin.file", "file")
    assert m.get("owner") == "root" and m.get("group") == "root", "hooks/ is root:root"
    assert str(m.get("mode")) == "0755" and m.get("recurse") is True, "0755 recursively — readable+executable, never writable"
    assert tasks[hooks[0]].get("become") is True
    assert hooks[0] > max(grants), "the hooks re-own must be the last word, after every grant"
    install = [t for t in tasks if (m := _mod(t, "ansible.builtin.copy", "copy"))
               and str(m.get("dest", "")).endswith("/hooks/update")]
    assert install and str(_mod(install[0], "ansible.builtin.copy", "copy").get("mode")) == "0755", \
        "the update hook is installed 0755 (readable + executable by every git actor, writable by none but root)"


def test_group_and_membership_precede_the_operator_push():
    """The group + membership tasks must come BEFORE the Mirror push (`git push local …`, run as the operator) —
    provisioning the write-grant after the push that needs it would be useless. Pins the ordering."""
    tasks = _tasks()
    def _idx(pred):
        return next((i for i, t in enumerate(tasks) if pred(t)), None)
    def _is_push(t):                                      # the Mirror push COMMAND only — not a task whose NAME
        m = _mod(t, "ansible.builtin.command", "command")  # merely mentions "git push local" (e.g. the user task)
        return bool(m) and "push local" in str(m.get("cmd", "")).lower()
    grp = _idx(lambda t: _mod(t, "ansible.builtin.group", "group"))
    usr = _idx(lambda t: _mod(t, "ansible.builtin.user", "user"))
    push = _idx(_is_push)
    assert grp is not None and usr is not None and push is not None, "missing group/user/push task"
    assert grp < push and usr < push, "the gid-1001 group + operator membership must be provisioned before the push"


def test_the_canonical_mirror_refuses_to_discard_promoted_work():
    """The mirror is a fast-forward-only push, and worktree/canonical diverge the moment propose-then-promote is
    used — a promote advances canonical `main` with a commit the worktree never had. The push then fails with
    git's generic "Updates were rejected... fetch first", which on a control plane reads like a transient git
    problem rather than "your promoted proposals live only in the canonical" (live-caught 2026-07-28: a deploy
    died here right after a hand-promote, with no indication why).

    Pins the actionable refusal AND, more importantly, that the remedy is never `--force`: force-pushing here
    would silently delete every promoted proposal the canonical holds."""
    with open(PLAYBOOK, encoding="utf-8") as fh:
        src = fh.read()
    assert "merge-base --is-ancestor FETCH_HEAD HEAD" in src, "the divergence check must exist"
    assert "REFUSING to mirror" in src and "would discard them" in src
    assert "--ff-only" in src, "the remedy must be a fast-forward merge, spelled out for the operator"
    pushes = [str(_mod(t, "ansible.builtin.command", "command").get("cmd", "")) for t in _tasks()
              if _mod(t, "ansible.builtin.command", "command") and "git push" in
              str(_mod(t, "ansible.builtin.command", "command").get("cmd", ""))]
    assert pushes, "the mirror push task must exist"
    assert all("--force" not in cmd and " -f " not in cmd for cmd in pushes),         "the mirror must never force-push the canonical: %r" % pushes
