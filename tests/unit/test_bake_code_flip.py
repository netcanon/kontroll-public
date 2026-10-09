"""Phase-B Rung 1b — the api fragment runs BAKED code, flag-gated, default-legacy (synthesis §5/§6).

WHY (the failures these guard): Rung 1b flips ONLY the api service to run code from the baked control image at
/opt/kontroll (working_dir/PYTHONPATH = KONTROLL_CODE_ROOT) while writing the C10 propose tree at /propose
(KONTROLL_WRITE_ROOT, the paths.write_root() seam). The flip MUST be (a) opt-in behind `bake_code` (default false) so
an un-baked deploy is byte-for-byte the legacy /repo path; (b) PER-SERVICE — onboard-gui + semaphore stay on /repo
until their own rungs (a big-bang flip would re-introduce the G9/audit/promote surfaces all at once); and (c) it must
NOT divert the deploy-time `paths.py resolve` CLI that the INSTALLER runs — that CLI is a third overlay-seam consumer
(review 30 §3) and the installer must keep KONTROLL_WRITE_ROOT UNSET so its secret-dir read stays on the canonical
clone (deploy-read == the same canonical instance/secrets the baked GUI writes). The `${…:-/repo}` defaults are the
identity that keeps the un-baked deploy unchanged.
"""
import os

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def test_api_fragment_runs_baked_code_when_flagged_else_legacy():
    """api.yaml must run code from KONTROLL_CODE_ROOT (baked /opt/kontroll or the legacy /repo) and address the
    propose tree via KONTROLL_WRITE_ROOT — both with a `:-/repo` default so an un-baked .env is byte-identical. The
    host clone dir stays …/api/repo (deploy-stack clones it unchanged); only the container mount TARGET is the
    write-root. Guards a hardcoded /repo that the bake_code flag can't flip, or a missing default that breaks the
    legacy deploy."""
    api = _read("docker/services/api.yaml")
    assert "working_dir: ${KONTROLL_CODE_ROOT:-/repo}" in api, "api working_dir must be the (baked-or-legacy) code root"
    assert "PYTHONPATH: ${KONTROLL_CODE_ROOT:-/repo}" in api, "api PYTHONPATH must be the (baked-or-legacy) code root"
    assert "KONTROLL_WRITE_ROOT: ${KONTROLL_WRITE_ROOT:-/repo}" in api, "api must pass the write-root into the container"
    assert "/api/repo:${KONTROLL_WRITE_ROOT:-/repo}" in api, \
        "the api content clone must mount at the write-root (the host dir stays …/api/repo)"


def test_only_semaphore_stays_legacy_after_rung2():
    """Rung 2 flips onboard-gui too (api flipped in 1b); only semaphore must NOT reference KONTROLL_CODE_ROOT — it
    keeps CLONING + running ansible/ from the canonical until Rung 3 (the promote-script seam, synthesis §2 Fork A /
    §1: baking ansible would decouple per-job playbooks from canonical versioning + break 'run exactly main').
    Guards a premature semaphore flip AND a regression that un-flips onboard-gui back to the /repo clone."""
    assert "${KONTROLL_CODE_ROOT" in _read("docker/services/onboard-gui.yaml"), \
        "onboard-gui flips to baked code in Rung 2 (mirrors the api flip — see test_bake_code_flip_gui.py)"
    assert "${KONTROLL_CODE_ROOT" not in _read("docker/services/semaphore.yaml"), \
        "semaphore must stay on /repo until Rung 3 (it clones ansible/ from the canonical for per-job 'run main')"


def test_deploy_stack_renders_bake_code_vars_gated_and_default_off():
    """deploy-stack must default `bake_code: false` (opt-in) and emit KONTROLL_CODE_ROOT=/opt/kontroll +
    KONTROLL_WRITE_ROOT=/propose into docker/.env ONLY under `{% if bake_code %}` — so the default deploy emits
    neither and the compose `:-/repo` defaults keep it byte-identical. Guards (a) the flag defaulting ON (a surprise
    bake) and (b) the vars emitted unconditionally (which would flip api even when bake_code is false)."""
    ds = _read("ansible/playbooks/deploy-stack.yml")
    assert "bake_code: false" in ds, "bake_code must default to false (opt-in, byte-identical default deploy)"
    assert "if bake_code" in ds, "the .env code-root vars must be GATED on bake_code (emitted only when baked)"
    assert "KONTROLL_CODE_ROOT=/opt/kontroll" in ds, "baked ⇒ the code root is the image bake path"
    assert "KONTROLL_WRITE_ROOT=/propose" in ds, "baked ⇒ the write root is the thin propose mount"


def test_installer_keeps_write_root_unset_for_the_deploy_cli():
    """V1 §3: the deploy-time `paths.py resolve ansible/secrets` CLI runs in the INSTALLER container; it is a third
    overlay-seam consumer and must resolve to the installer's /repo canonical clone (deploy-read == the canonical
    instance/secrets the baked GUI also writes). So installer.yaml must NOT set KONTROLL_WRITE_ROOT — leaving it
    unset keeps paths.write_root()==ROOT==/repo there. Guards a future edit that exports the bake write-root into the
    installer env, which would silently divert the deploy-time secret read off the canonical clone."""
    assert "KONTROLL_WRITE_ROOT" not in _read("docker/services/installer.yaml"), \
        "the installer must keep KONTROLL_WRITE_ROOT unset so the deploy-time paths.py resolve stays on its /repo clone"
