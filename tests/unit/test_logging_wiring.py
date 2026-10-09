"""Pins the device-side logging WIRING layer so the blind-joe ENACT path can't reference phantom artifacts.

logsvc.logging_enact_commands emits, for a PUSH logging method, an `ansible-playbook wire-logging.yml -e
role=<wiring_role> -e target=<key>` step the operator runs to make logs flow. Nothing in the pure-python test
suite would notice if that playbook, the named role, or the backend entrypoint the role delegates to didn't
exist — the enact would simply fail at apply time on the operator's machine. These tests make the enact
contract real: every wiring_role a method names is a built role (with a backup entrypoint per CLAUDE.md), the
dispatcher exists, and the backend `configure` entrypoint the syslog push path needs is present.
"""
import os

import pytest

from kontroll import catalog, paths

pytestmark = pytest.mark.unit

ROLES = os.path.join(paths.ROOT, "ansible", "roles")
PLAYBOOKS = os.path.join(paths.ROOT, "ansible", "playbooks")


def test_wire_logging_dispatcher_playbook_exists():
    """The dispatcher logsvc.logging_enact_commands references (ansible/playbooks/wire-logging.yml) must exist,
    or every push-method ENACT step points at a playbook that isn't there (the failure that shipped: the enact
    string referenced wire-logging.yml before it was built)."""
    assert os.path.exists(os.path.join(PLAYBOOKS, "wire-logging.yml"))


def test_every_named_wiring_role_is_built_with_a_backup_entrypoint():
    """Each logging method that declares a wiring_role must be a real role with tasks/main.yml (the wiring),
    tasks/backup.yml (the rollback reference — CLAUDE.md: new roles carry a backup entrypoint), and a README.
    Guards a descriptor naming a role that was never built — the include_role would fail at apply time."""
    referenced = sorted({m.get("wiring_role") for m in catalog.load_logging() if m.get("wiring_role")})
    assert referenced, "expected at least syslog_push to declare a wiring_role"
    for role in referenced:
        rdir = os.path.join(ROLES, role)
        assert os.path.exists(os.path.join(rdir, "tasks", "main.yml")), "%s: no tasks/main.yml" % role
        assert os.path.exists(os.path.join(rdir, "tasks", "backup.yml")), "%s: no tasks/backup.yml" % role
        assert os.path.exists(os.path.join(rdir, "README.md")), "%s: no README.md" % role


def test_backend_configure_entrypoint_exists_for_syslog_push():
    """syslog_push's wiring role delegates to backend_netcommon_cli `tasks_from: configure` (the device_role
    dispatch seam) — that entrypoint had to be added (the backend previously had only check/backup). Guards
    include_role resolving a missing tasks file at apply time."""
    assert os.path.exists(os.path.join(ROLES, "backend_netcommon_cli", "tasks", "configure.yml"))
