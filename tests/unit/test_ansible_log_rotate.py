"""deploy-stack — the ansible run-log logrotate bound (G5).

The control node's ansible run-log is written via `ansible.cfg` `log_path` (ANSIBLE_LOG_PATH ->
/var/lib/kontroll/ansible-log/ansible.log, persisted across the Semaphore job clone, tailed RO by Vector). Unlike
the API/GUI audit logs (which self-rotate via a Python RotatingFileHandler bounded by KONTROLL_AUDIT_MAX_*), ansible's
log_path simply APPENDS forever — so without a bound the run-log grows without limit (the deferred G5 gap). deploy-stack
drops a host logrotate config that caps it.

Two contracts are pinned as text assertions on deploy-stack.yml (they fail loudly if a future edit drops the bound or
breaks the tailer):

  1. BOUNDED — the drop-in sizes + counts the rotations from kontroll_ansible_log_max_mb / _max_files (defaulted), so
     the file can never grow unbounded again.
  2. copytruncate is LOAD-BEARING — Vector tails the run-log by EXACT path (internal_ansible.yaml reads
     /host/ansible-log/ansible.log, not a glob). A rotate-by-rename (logrotate's default create mode) would move the
     inode to ansible.log.1 and orphan Vector's tail on the old inode; copytruncate keeps the same inode (truncating in
     place) so the tail survives rotation. Guards a regression to rename-rotation that would silently sever log shipping.
"""
import os

import pytest

pytestmark = pytest.mark.unit

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _deploy_stack():
    with open(os.path.join(_ROOT, "ansible", "playbooks", "deploy-stack.yml"), encoding="utf-8") as fh:
        return fh.read()


def test_logrotate_dropin_is_written_for_the_ansible_run_log():
    """deploy-stack drops /etc/logrotate.d/kontroll-ansible-log targeting the ansible-log dir's *.log. Guards the
    run-log losing its rotation config entirely (back to the unbounded-growth G5 gap)."""
    ds = _deploy_stack()
    assert "dest: /etc/logrotate.d/kontroll-ansible-log" in ds, \
        "deploy-stack must write the ansible run-log logrotate drop-in"
    assert "{{ kontroll_ansible_log_dir }}/*.log {" in ds, \
        "the drop-in must target the configured ansible-log dir (not a hard-coded path)"


def test_logrotate_is_bounded_by_the_size_and_count_knobs():
    """The drop-in sizes rotation from kontroll_ansible_log_max_mb and keeps kontroll_ansible_log_max_files backups —
    both defaulted, so a no-override deploy still bounds the file. Guards an edit that drops the `size`/`rotate`
    directives (which would make logrotate a no-op and re-open unbounded growth)."""
    ds = _deploy_stack()
    assert "size {{ kontroll_ansible_log_max_mb | default(5) }}M" in ds, \
        "rotation must be size-triggered from kontroll_ansible_log_max_mb (defaulted)"
    assert "rotate {{ kontroll_ansible_log_max_files | default(5) }}" in ds, \
        "the backup count must come from kontroll_ansible_log_max_files (defaulted)"


def test_logrotate_uses_copytruncate_to_not_break_vectors_tail():
    """The drop-in MUST use copytruncate — Vector tails the run-log by exact path, so rename-rotation would orphan its
    tail on the old inode. copytruncate keeps the inode. This is the load-bearing invariant of the whole change."""
    ds = _deploy_stack()
    assert "copytruncate" in ds, \
        "the run-log rotation must use copytruncate (Vector tails the exact path; rename-rotation severs the tail)"


def test_logrotate_package_is_ensured_present():
    """deploy-stack ensures the `logrotate` package is installed before relying on its drop-in. Guards a host where
    logrotate was removed (the drop-in would be inert and the bound silently absent)."""
    ds = _deploy_stack()
    assert "name: logrotate" in ds, "deploy-stack must ensure the logrotate package is present"
