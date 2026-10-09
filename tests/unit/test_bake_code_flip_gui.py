"""Phase-B Rung 2 — the onboard-gui fragment runs BAKED code, plus the M11 audit-log repoint (synthesis §2/§3/§5).

WHY (the failures these guard): Rung 2 flips the HIGHER-privilege onboard-gui service (it holds the age key + the
widest propose surface: onboard/secrets/keygen/actuation/reconfigure/regen) to run code from the baked control image
at /opt/kontroll while writing the C10 propose tree at /propose (paths.write_root()). Two Rung-2-specific hazards:
  * a hardcoded /repo the bake_code flag can't flip, or a missing `:-/repo` default that breaks the legacy deploy;
  * M11 — the GUI audit log lived at /repo/local/onboard-gui-audit.log INSIDE the content clone, which (a) is
    read-only under a baked /opt/kontroll and (b) gets wiped by the content-clone `reset --hard`. It must move to a
    dedicated /audit bind (KONTROLL_GUI_AUDIT_DIR), the Vector tail must FOLLOW it off …/onboard-gui/repo/local, and
    deploy-stack must provision the new host dir uid-scoped (else `compose up` auto-creates it root:root 0755 — a
    C8/C12 at-rest leak the storage guard exists to catch).
"""
import os

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def test_onboard_gui_fragment_runs_baked_code_when_flagged_else_legacy():
    """onboard-gui.yaml must run gui/app.py from KONTROLL_CODE_ROOT (baked /opt/kontroll or the legacy /repo), set
    ANSIBLE_ROLES_PATH under the same code root, address the propose tree via KONTROLL_WRITE_ROOT, and mount the
    content clone at the write-root — every reference with a `:-/repo` default so an un-baked .env is byte-identical.
    Mirrors the api flip (test_bake_code_flip.py). Guards a hardcoded /repo the flag can't flip."""
    gui = _read("docker/services/onboard-gui.yaml")
    assert "working_dir: ${KONTROLL_CODE_ROOT:-/repo}" in gui, "working_dir must be the (baked-or-legacy) code root"
    assert "python3 ${KONTROLL_CODE_ROOT:-/repo}/gui/app.py" in gui, "the app entrypoint must run from the code root"
    assert "ANSIBLE_ROLES_PATH: ${KONTROLL_CODE_ROOT:-/repo}/ansible/roles" in gui, "roles path follows the code root"
    assert "KONTROLL_WRITE_ROOT: ${KONTROLL_WRITE_ROOT:-/repo}" in gui, "onboard-gui must pass the write-root in"
    assert "/onboard-gui/repo:${KONTROLL_WRITE_ROOT:-/repo}" in gui, \
        "the content clone must mount at the write-root (the host dir stays …/onboard-gui/repo)"


def test_onboard_gui_audit_log_is_off_the_code_propose_tree():
    """M11: the GUI audit log must be at the dedicated /audit bind (KONTROLL_GUI_AUDIT_DIR), NEVER inside the
    /repo content clone — so it survives a read-only baked code root AND the clone `reset --hard`. Guards a
    regression back to /repo/local (which breaks the moment onboard-gui is baked)."""
    gui = _read("docker/services/onboard-gui.yaml")
    assert "GUI_AUDIT_LOG: /audit/onboard-gui-audit.log" in gui, "the audit log must live on the dedicated /audit bind"
    assert "/repo/local/onboard-gui-audit.log" not in gui, "the audit log must NOT be inside the code/propose clone"
    assert "${KONTROLL_GUI_AUDIT_DIR:-/var/lib/kontroll/onboard-gui/audit}:/audit" in gui, \
        "the /audit bind source must be the fail-closed KONTROLL_GUI_AUDIT_DIR (mirrors api's KONTROLL_API_AUDIT_DIR)"


def test_vector_tail_follows_the_relocated_gui_audit_log():
    """The Vector GUI-audit source mount must follow the audit log to KONTROLL_GUI_AUDIT_DIR — leaving it on the
    old …/onboard-gui/repo/local path would silently orphan the tail (the audit trail stops reaching Loki, a C12
    logging gap). The in-container source path (/host/gui-audit/onboard-gui-audit.log) is unchanged; only the host
    bind source moves, exactly mirroring api's KONTROLL_API_AUDIT_DIR:/host/api-audit."""
    vec = _read("docker/services/vector.yaml")
    assert "${KONTROLL_GUI_AUDIT_DIR:-/var/lib/kontroll/onboard-gui/audit}:/host/gui-audit:ro" in vec, \
        "Vector must tail the relocated GUI audit dir"
    assert "/onboard-gui/repo/local:/host/gui-audit" not in vec, "the Vector tail must not point at the old repo/local path"


def test_deploy_stack_provisions_and_renders_the_gui_audit_dir():
    """deploy-stack must (a) derive kontroll_gui_audit_dir with the today-exact default, (b) render
    KONTROLL_GUI_AUDIT_DIR into docker/.env, and (c) provision the host dir uid-1001 (so `compose up` never
    auto-creates it root:root — the C8 at-rest hole the storage guard catches). Guards a bind with no provisioner."""
    ds = _read("ansible/playbooks/deploy-stack.yml")
    assert "kontroll_gui_audit_dir" in ds, "the GUI audit dir fact must be derived"
    assert "KONTROLL_GUI_AUDIT_DIR={{ kontroll_gui_audit_dir }}" in ds, "the GUI audit dir must be rendered into .env"
    assert "onboard-gui audit-log dir" in ds, "deploy-stack must provision the GUI audit dir uid-scoped (M11/C8)"


def test_gui_audit_dir_is_a_reserved_platform_core_env_var():
    """KONTROLL_GUI_AUDIT_DIR is a platform-core .env literal, so a device/consumer secret_env_map must never be
    allowed to shadow it — it must be in gen-secret-env's RESERVED_PLATFORM_CORE_ENV (the covering drift test pins
    the set to the deploy-stack .env lines). Guards the reserved set falling out of sync with the new render line."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gen_secret_env", os.path.join(ROOT, "scripts", "gen-secret-env.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert "KONTROLL_GUI_AUDIT_DIR" in mod.RESERVED_PLATFORM_CORE_ENV
