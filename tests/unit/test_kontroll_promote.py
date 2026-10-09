"""kontroll-promote.py — the FIX-M9 pin-conflict gate before the fast-forward promote.

WHY (the failures these guard):
  * Two app-store units each pinning the SAME collection to a DIFFERENT exact `==` version both becoming `active`
    makes `gen-requirements` fail closed at GENERATE time — which halts the NEXT deploy's pre-image-build, a brick
    one seam removed from the cause. The promote gate must REFUSE such a promote (and NEVER advance `main`), so two
    conflicting `==` units can never co-exist. A clean proposal must still promote, and the gate must fail OPEN on
    its own read error (it hardens; it must never itself block a clean promote).
  * The detector is the proposal's OWN `gen-requirements.py --conflict-check` run over the extracted prospective
    tree — so the wiring (archive → extract → run → refuse on non-zero) is exercised end-to-end against real git +
    subprocess, not only a mock (the L2b lesson: a mock hides the plumbing bug).
"""
import importlib.util
import os
import shutil
import subprocess as sp

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_script(modname, filename):
    """Load a hyphenated scripts/<filename> by path (not importable as a module name)."""
    spec = importlib.util.spec_from_file_location(modname, os.path.join(ROOT, "scripts", filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


promote = _load_script("kontroll_promote", "kontroll-promote.py")


def test_promote_refused_on_pin_conflict(monkeypatch):
    """A proposal whose prospective tree fails the conflict-check is REFUSED — `promote_ref` is NEVER called and the
    exit is non-zero (2). Guards two conflicting `==` units both reaching `main` and bricking a later deploy."""
    monkeypatch.setattr(promote, "_would_brick_generate", lambda run_id, repo: "pin conflict: community.docker")
    called = []
    monkeypatch.setattr(promote.gitio, "promote_ref", lambda *a, **k: called.append(1) or True)
    assert promote.main(["deadbeef", "--repo", "/srv/kontroll.git"]) == 2 and called == []


def test_promote_proceeds_when_clean(monkeypatch):
    """A clean proposal (the gate returns None) promotes — `promote_ref` runs with the run_id and the rc is 0."""
    monkeypatch.setattr(promote, "_would_brick_generate", lambda run_id, repo: None)
    called = []
    monkeypatch.setattr(promote.gitio, "promote_ref", lambda run_id, cwd=None: called.append(run_id) or True)
    assert promote.main(["deadbeef"]) == 0 and called == ["deadbeef"]


def test_skip_flag_bypasses_the_gate(monkeypatch):
    """--skip-conflict-check is the documented emergency override: it bypasses the gate so `promote_ref` runs even
    when the gate WOULD refuse. Guards the escape hatch (and that the gate is otherwise on by default)."""
    monkeypatch.setattr(promote, "_would_brick_generate", lambda *a, **k: "conflict (would normally refuse)")
    called = []
    monkeypatch.setattr(promote.gitio, "promote_ref", lambda *a, **k: called.append(1) or True)
    assert promote.main(["deadbeef", "--skip-conflict-check"]) == 0 and called == [1]


def _unit(repo, key, ver):
    """Write a minimal active community.docker unit pinning `ver` under the repo's instance overlay."""
    d = repo / "instance" / "actuation" / key
    d.mkdir(parents=True)
    (d / "unit.yml").write_text(yaml.safe_dump({
        "schema": 1, "key": key, "status": "active",
        "unit": {"kind": "role", "collection": "community.docker", "name": key},
        "install": {"collections": [{"name": "community.docker", "version": ver}]},
        "target": {"device_class": "docker_host", "inventory_group": "docker_hosts", "blast_radius": "LAN"}}),
        encoding="utf-8")


def test_would_brick_generate_detects_a_real_conflict(tmp_path):
    """End-to-end (real git + subprocess): a `proposed/<id>` ref whose tree has two `==`-conflicting active units
    makes `_would_brick_generate` return a conflict message naming the collection; a single-unit tree returns None.
    Proves the archive → extract → proposal's-own `gen-requirements --conflict-check` plumbing actually detects (a
    mock would hide a cwd/path/extract bug — the L2b lesson)."""
    repo = tmp_path / "repo"
    shutil.copytree(os.path.join(ROOT, "scripts"), repo / "scripts")
    (repo / "modules").mkdir()
    shutil.copy(os.path.join(ROOT, "modules", "_core.yml"), repo / "modules" / "_core.yml")
    for rel in ("config", "instance"):
        (repo / rel).mkdir(parents=True, exist_ok=True)
        (repo / rel / "fleet.yml").write_text("enabled_modules: [docker_host]\n", encoding="utf-8")
    _unit(repo, "dock_a", "==1.0.0")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    for cmd in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-qm", "one"],
                ["git", "branch", "proposed/clean"]):
        sp.run(cmd, cwd=repo, env=env, check=True)
    assert promote._would_brick_generate("clean", str(repo)) is None        # one unit → no conflict → proceed
    _unit(repo, "dock_b", "==2.0.0")                                        # a second, conflicting `==` pin
    for cmd in (["git", "add", "-A"], ["git", "commit", "-qm", "two"], ["git", "branch", "proposed/conflict"]):
        sp.run(cmd, cwd=repo, env=env, check=True)
    msg = promote._would_brick_generate("conflict", str(repo))
    assert msg and "community.docker" in msg and "conflict" in msg.lower()  # the gate would REFUSE this promote
