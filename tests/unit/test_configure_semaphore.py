"""scripts/configure-semaphore.py — the operational-template drop-in registry (config/semaphore/templates/).

Verifies the data-driven registration that replaced the inline ping-fleet: the loader reads every template
spec, the C10 `promote-proposal` template declares its `run_id` survey variable, every registered playbook
actually exists, and `template_payload` threads survey_vars/arguments ONLY when declared.

Why each guards a real failure:
- A registry that silently dropped a template file would leave an operational task (e.g. the promote "approve"
  action) unregistered in Semaphore with no error — the loader must return exactly the declared set.
- A `promote-proposal` missing its required `run_id` survey var would make the GUI promote unusable (no way to
  name the proposal), or worse, promote with an undefined id.
- A template pointing at a typo'd `playbook:` path would fail only at Semaphore runtime — the existence check
  turns that into a CI failure (config-as-data, validated).
- Threading an EMPTY survey_vars onto ping-fleet would churn its template on every re-run (a non-idempotent
  upsert) and is semantically wrong (ping takes no input).
"""
import importlib.util
import os
import types

import pytest

from kontroll import paths

pytestmark = pytest.mark.unit


def _load():
    """Load scripts/configure-semaphore.py (hyphenated → not importable by name) as a module."""
    path = os.path.join(paths.ROOT, "scripts", "configure-semaphore.py")
    spec = importlib.util.spec_from_file_location("configure_semaphore", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cs = _load()


def test_registry_loads_ping_and_promote_with_required_keys():
    """The loader returns one spec per config/semaphore/templates/*.yml, each with name+playbook+description,
    and includes both the migrated ping-fleet and the new promote-proposal."""
    specs = cs.load_operational_templates()
    by_name = {s["name"]: s for s in specs}
    assert {"ping-fleet", "promote-proposal"} <= set(by_name)
    for s in specs:
        assert s.get("name") and s.get("playbook") and s.get("description"), s.get("_file")


def test_promote_proposal_declares_required_run_id_survey_var():
    """promote-proposal exposes exactly the `run_id` survey variable, required — the operator must name the
    proposal to promote; ping-fleet, which takes no input, declares no survey vars."""
    by_name = {s["name"]: s for s in cs.load_operational_templates()}
    sv = by_name["promote-proposal"].get("survey_vars")
    assert sv and len(sv) == 1
    assert sv[0]["name"] == "run_id" and sv[0]["required"] is True
    assert not by_name["ping-fleet"].get("survey_vars")


def test_every_registered_playbook_exists():
    """Each template's repo-relative playbook path resolves to a real file — a typo would otherwise surface
    only when Semaphore runs the job."""
    for s in cs.load_operational_templates():
        assert os.path.isfile(os.path.join(paths.ROOT, s["playbook"])), s["playbook"]


def test_template_payload_threads_survey_vars_and_arguments_only_when_present():
    """template_payload includes survey_vars/arguments ONLY when the spec declares them (so a no-input template
    carries no empty survey_vars and re-runs don't churn), and always carries the common project ids."""
    common = {"project_id": 1, "inventory_id": 2, "repository_id": 3, "environment_id": 4,
              "app": "ansible", "type": "", "arguments": "[]"}

    promote = {"name": "promote-proposal", "playbook": "ansible/playbooks/promote.yml",
               "description": "d", "survey_vars": [{"name": "run_id", "required": True}]}
    p = cs.template_payload(promote, common)
    assert p["survey_vars"] == promote["survey_vars"]
    assert p["name"] == "promote-proposal" and p["project_id"] == 1

    ping = {"name": "ping-fleet", "playbook": "ansible/playbooks/ping.yml", "description": "d"}
    p2 = cs.template_payload(ping, common)
    assert "survey_vars" not in p2

    with_args = {"name": "x", "playbook": "ansible/playbooks/ping.yml", "description": "d",
                 "arguments": ["-e", "k=v"]}
    p3 = cs.template_payload(with_args, common)
    assert p3["arguments"] == '["-e", "k=v"]'        # JSON-serialised


def test_wait_for_semaphore_retries_until_it_responds(monkeypatch):
    """F15 (live single-pass dogfood): Semaphore's HTTP server isn't listening the instant deploy-stack starts its
    container, so configure-semaphore must POLL past transient connection failures and proceed once it RESPONDS —
    else a fresh deploy-then-configure flow races it with a ConnectionResetError. Mocks urlopen to fail twice then
    succeed (and sleep to a no-op); asserts it returns after the server comes up, not on the first refusal."""
    import urllib.error
    calls = {"n": 0}

    def fake_open(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("connection refused")
        return object()                               # any response object → the server is up
    monkeypatch.setattr(cs.urllib.request, "urlopen", fake_open)
    monkeypatch.setattr(cs.time, "sleep", lambda s: None)
    cs.wait_for_semaphore(timeout=30)                 # returns without raising, after the 3rd poll
    assert calls["n"] == 3


def test_admin_password_self_decrypts_from_sops_when_env_absent(monkeypatch, tmp_path):
    """Without SEMAPHORE_ADMIN_PASSWORD in the env, configure-semaphore SELF-DECRYPTS it from the semaphore SOPS
    domain via `sops -d --extract '["semaphore_admin_password"]'` — so the documented `python3 scripts/configure-
    semaphore.py` works on the control node with NO manual export. The live fresh-install dogfood failed with
    'SEMAPHORE_ADMIN_PASSWORD not set' precisely because that export was undocumented; this guards the fallback. An
    env value, when present, WINS and no decrypt runs (never re-shells sops when the operator already supplied it)."""
    monkeypatch.delenv("SEMAPHORE_ADMIN_PASSWORD", raising=False)
    secrets = tmp_path / "semaphore.sops.yml"
    secrets.write_text("encrypted", encoding="utf-8")
    monkeypatch.setattr(cs, "SEMAPHORE_SECRETS", str(secrets))
    calls = {}

    def fake_run(argv, capture_output=False, text=False):
        calls["argv"] = argv
        return types.SimpleNamespace(returncode=0, stdout="s3cret-from-sops\n", stderr="")
    monkeypatch.setattr(cs.subprocess, "run", fake_run)

    assert cs.admin_password() == "s3cret-from-sops"
    assert calls["argv"][:3] == ["sops", "-d", "--extract"]
    assert '["semaphore_admin_password"]' in calls["argv"] and str(secrets) in calls["argv"]

    monkeypatch.setenv("SEMAPHORE_ADMIN_PASSWORD", "from-env")
    calls.clear()
    assert cs.admin_password() == "from-env"
    assert not calls                                  # env wins → sops was never invoked


def test_admin_password_none_when_no_env_and_no_secrets_file(monkeypatch, tmp_path):
    """No env var AND no instance/secrets/semaphore.sops.yml (a half-provisioned node) ⇒ admin_password() returns
    None — so main() fails with a clear hint instead of crashing in sops — and sops is NOT invoked when the file is
    absent (no spurious subprocess on a node that hasn't minted the semaphore domain yet)."""
    monkeypatch.delenv("SEMAPHORE_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(cs, "SEMAPHORE_SECRETS", str(tmp_path / "absent.sops.yml"))
    called = {"n": 0}
    monkeypatch.setattr(cs.subprocess, "run", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    assert cs.admin_password() is None
    assert called["n"] == 0
