"""deploy-stack.yml: read-only RESOLVER tasks must run under `--check` (`check_mode: false`).

WHY (the failure this guards — hit LIVE 2026-06-21 while arming the onboard-gui GUI propose path on prod):
the play resolves a few facts with `ansible.builtin.command` tasks that `register:` a var the `.env` render
+ early play vars then dereference — most critically `_secrets_dir_resolved.stdout` -> the `_secrets_dir`
play var -> every `community.sops.sops` lookup. A plain `command` task is SKIPPED under `--check`, so the
register is never set: `_secrets_dir` collapses to '' and the "Render docker/.env" task dies with
`could not locate file in lookup: /semaphore.sops.yml` (an absolute path = empty dir). That made the
CLAUDE.md-mandated `--check --diff` dry-run UNUSABLE for the stack's most important playbook.

The fix tags each read-only resolver `check_mode: false` so it executes even in check mode — they only
RESOLVE a path/flag/GID (no mutation), so running them under --check is safe. This test pins that tag on
every resolver (matched by its `register:` name, recursing into blocks), pins the keystone _secrets_dir
resolver explicitly, and pins the resolver-vs-mutator boundary (the `up`/`gen-*` tasks must STAY
check-skipped so a dry-run never actuates). A resolver that loses the tag — or a new SOPS-feeding resolver
added without it — re-breaks `--check`; this fails loud first.
"""
import os

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEPLOY = os.path.join(ROOT, "ansible", "playbooks", "deploy-stack.yml")

# Read-only resolvers whose registered stdout feeds the .env render / early play vars -> MUST run in --check.
# The first four are UNGATED and feed the render directly (the exact bug); the last two are gated read-only
# resolvers (getent journal GID for vector; Caddyfile text for acme) flipped for full --check fidelity.
_RESOLVERS = {
    "_secrets_dir_resolved",   # paths.py resolve  -> _secrets_dir -> every SOPS lookup (the keystone)
    "_uvicorn_extra",          # frontend.py uvicorn-extra -> KONTROLL_API_UVICORN_EXTRA
    "_needs_cert",             # frontend.py needs-cert    -> GUI_TLS_CERT/KEY + cert tasks
    "_runs_caddy",             # frontend.py runs-caddy    -> caddy gating + _up_services
    "_journal_grp",            # getent group systemd-journal -> KONTROLL_JOURNAL_GID (gated on vector)
    "_caddyfile",              # frontend.py caddyfile     -> the rendered Caddyfile (gated on acme)
    "_img_env",                # gen-image-digests.py --env -> the published @sha256 pins (gated on use_published_images)
}


def _walk(tasks):
    """Yield every leaf task dict, recursing into block/rescue/always containers."""
    for t in tasks or []:
        if not isinstance(t, dict):
            continue
        nested = False
        for key in ("block", "rescue", "always"):
            if isinstance(t.get(key), list):
                nested = True
                yield from _walk(t[key])
        if not nested:
            yield t


def _all_tasks():
    plays = yaml.safe_load(open(DEPLOY, encoding="utf-8"))
    out = []
    for play in plays if isinstance(plays, list) else []:
        if not isinstance(play, dict):
            continue
        for section in ("pre_tasks", "tasks", "post_tasks"):
            out += list(_walk(play.get(section)))
    return out


def _by_register():
    return {t["register"]: t for t in _all_tasks() if t.get("register")}


def _cmd_str(t):
    for k in ("ansible.builtin.command", "command", "ansible.builtin.shell", "shell"):
        v = t.get(k)
        if isinstance(v, dict):
            return str(v.get("cmd", ""))
        if v is not None:
            return str(v)
    return ""


@pytest.mark.parametrize("reg", sorted(_RESOLVERS))
def test_resolver_runs_in_check_mode(reg):
    """Each read-only resolver (by `register:` name) carries `check_mode: false` so `--check` executes it —
    else its register is empty under --check and the downstream .env render / gated branch fails. Guards the
    live 2026-06-21 `_secrets_dir`-empty-on-check regression."""
    tasks = _by_register()
    assert reg in tasks, "no task registers %s in deploy-stack.yml (resolver renamed/removed?)" % reg
    cm = tasks[reg].get("check_mode")
    assert cm is False, (
        "resolver %s must set `check_mode: false` (got %r) so it runs under --check; without it the "
        "--check dry-run breaks at the .env render" % (reg, cm)
    )


def test_secrets_dir_resolver_keystone():
    """The `_secrets_dir_resolved` task — the exact one whose check-skip emptied `_secrets_dir` — exists, is
    the read-only `paths.py resolve` command, and carries check_mode:false + changed_when:false. Pinned
    explicitly so a refactor that drops/renames the keystone of the regression is caught loudly."""
    t = _by_register().get("_secrets_dir_resolved")
    assert t is not None, "the _secrets_dir_resolved resolver is gone — _secrets_dir would break under --check"
    assert t.get("check_mode") is False, "the keystone resolver must be check_mode:false"
    assert t.get("changed_when") is False, "the resolver is read-only — keep changed_when:false"
    assert "paths.py resolve" in _cmd_str(t), "the resolver should run scripts/kontroll/paths.py resolve"


def test_mutating_tasks_are_not_check_mode_false():
    """The compose `up` and the `gen-*` regenerators MUTATE (start containers / write generated files); they
    must STAY check-skipped (never check_mode:false) so a `--check` dry-run never actuates. Pins the
    resolver-vs-mutator boundary the fix draws, so a future careless `check_mode: false` on a writer is caught."""
    offenders = []
    for t in _all_tasks():
        cmd = _cmd_str(t)
        # A gen-* call MUTATES only when it WRITES (the regenerators); its read-only modes (`--env`, `--check`) are
        # resolvers, not writers — e.g. gen-image-digests.py --env reads the lock to feed the .env pin (C0).
        gen_writes = "scripts/gen-" in cmd and "--check" not in cmd and "--env" not in cmd
        mutates = ("compose" in cmd and "up" in cmd) or gen_writes
        if mutates and t.get("check_mode") is False:
            offenders.append(t.get("name"))
    assert not offenders, "mutating task(s) must NOT be check_mode:false (would actuate during --check): %r" % offenders
