"""roles/logging_journald_receiver — the collector-side journald-upload receiver (S10).

Codifies the security + correctness contract proven on the live bench (local/s10-journald-receiver-bench-findings.md;
the reverted http_server PR #12/#13): the receiver runs systemd-journal-remote bound to the MGMT IP ONLY (never
0.0.0.0 — C3/C12) via `--listen-http=<mgmt>:<port>`, writes a SEPARATE top-level dir (/var/log/journal-remote, not
under /var/log/journal, so the internal_journald source can't double-ingest), and ships the role idioms kontroll
requires (an asserted required mgmt host, a backup entrypoint). These are text assertions on the role files — they
fail loudly if a future edit reintroduces a 0.0.0.0 bind or the under-/var/log/journal collision.
"""
import os

import pytest
import yaml

pytestmark = pytest.mark.unit

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ROLE = os.path.join(_ROOT, "ansible", "roles", "logging_journald_receiver")


def _read(rel):
    with open(os.path.join(_ROLE, rel), encoding="utf-8") as fh:
        return fh.read()


def test_role_has_the_kontroll_role_idioms():
    """The receiver role ships the entrypoints kontroll requires of a state-changing role: a default `main`, a
    `backup` rollback entrypoint, handlers, and a defaults file (CLAUDE.md). Guards a half-built role that can't
    be rolled back or that has no port default."""
    for rel in ("tasks/main.yml", "tasks/backup.yml", "handlers/main.yml", "defaults/main.yml"):
        assert os.path.exists(os.path.join(_ROLE, rel)), "logging_journald_receiver missing %s" % rel
    assert "logging_journald_upload_port" in _read("defaults/main.yml"), "the receiver port needs a default"


def test_receiver_binds_the_mgmt_ip_only_never_0_0_0_0():
    """The receiver's systemd-journal-remote service binds `--listen-http={{ logging_collector_host }}:<port>` — a
    TEMPLATED specific IP, never a bare port and never 0.0.0.0. A bare `--listen-http=<port>` would listen on ALL
    interfaces, exposing :19532 on the WAN side of a multi-homed control node (SECURITY.md C3/C12). LIVE-verified
    on the bench: `--listen-http=127.0.0.1:19532` bound loopback ONLY. Also pins the role ASSERTS the mgmt host is
    supplied (so it can never silently fall back to an all-interfaces bind)."""
    unit = _read("templates/kontroll-journal-remote.service.j2")
    assert "--listen-http={{ logging_collector_host }}:" in unit, \
        "receiver unit must bind --listen-http=<mgmt IP>:<port> (a specific IP, never a bare port / 0.0.0.0)"
    assert "--listen-http={{ logging_collector_host }}:{{ logging_journald_upload_port" in unit or \
        "--listen-http={{ logging_collector_host }}:" in unit, "the bind IP must be the templated mgmt host"
    assert _read("tasks/main.yml").count("logging_collector_host | default('') | length > 0") == 1, \
        "the role must ASSERT logging_collector_host is set (never silently bind all interfaces)"


def test_receiver_writes_a_separate_dir_not_under_var_log_journal():
    """The receiver writes /var/log/journal-remote (a SEPARATE top-level dir), NOT /var/log/journal/remote (a
    subdir of the LOCAL journal the internal_journald source reads). Under /var/log/journal the uploads would be
    double-ingested — once as source=internal, once as source=capability (the internal source's current_boot_only
    only accidentally hides them). Pins the collision-free path so a future edit can't move it back under the
    local journal dir."""
    unit = _read("templates/kontroll-journal-remote.service.j2")
    main = _read("tasks/main.yml")
    assert "--output=/var/log/journal-remote/" in unit, "receiver unit must write the SEPARATE /var/log/journal-remote"
    assert "/var/log/journal/remote" not in unit and "/var/log/journal/remote" not in main, \
        "must NOT write under /var/log/journal (internal_journald reads it -> double-ingestion)"
    assert "path: /var/log/journal-remote" in main, "the role must create the separate output dir"


def test_receiver_runs_as_journal_remote_user_not_root():
    """The receiver unit runs as User=systemd-journal-remote (the package's own non-root user), Group=systemd-journal
    (so its .journal output is group-readable by the same gid host journald uses, and Vector reads BOTH via one gid
    grant), with NoNewPrivileges. Guards a regression to an implicit root run (C12 residual 3) — a network-facing
    UNAUTHENTICATED listener must not run root."""
    unit = _read("templates/kontroll-journal-remote.service.j2")
    assert "User=systemd-journal-remote" in unit, "receiver must run as systemd-journal-remote, not root"
    assert "Group=systemd-journal" in unit, "output group must be systemd-journal (the shared read gid)"
    assert "NoNewPrivileges=true" in unit, "keep NoNewPrivileges on the receiver unit"


def test_receiver_output_dir_is_setgid_group_readable_not_world():
    """The output dir is 2750 owner=systemd-journal-remote group=systemd-journal: setgid so .journal files inherit
    the read gid, group-readable so Vector reads them, NOT world-readable (tightens the prior 0755). Guards the dir
    reverting to 0755/root (world-readable journal bodies) or losing the setgid (files would not inherit the gid
    Vector reads by)."""
    main = _read("tasks/main.yml")
    assert 'mode: "2750"' in main, "the output dir must be 2750 (setgid, group-read, not world)"
    assert "group: systemd-journal" in main, "the output dir group must be systemd-journal (Vector's read gid)"
    assert "owner: systemd-journal-remote" in main, "the output dir owner must be the non-root receiver user"


def test_descriptor_exec_command_reads_the_same_separate_dir():
    """The journald_remote descriptor's exec journalctl reads the SAME separate dir the receiver writes — the two
    halves must agree on /var/log/journal-remote, else Vector tails an empty dir. Guards the receiver-output and
    the Vector-read paths drifting apart."""
    with open(os.path.join(_ROOT, "logging", "journald_remote.yml"), encoding="utf-8") as fh:
        d = yaml.safe_load(fh)
    assert "--directory=/var/log/journal-remote" in d["source"]["command"], \
        "the exec journalctl --directory must match the receiver --output (/var/log/journal-remote)"


def test_vector_bind_mounts_the_remote_journal_dir_ro():
    """vector.yaml bind-mounts /var/log/journal-remote READ-ONLY, so the journald_remote exec source's journalctl
    can read the receiver's output (RO — Vector reads, never writes; C12). Closes the loop: receiver --output ->
    this mount -> the exec --directory. Guards the mount being dropped (the exec source would tail an empty dir)."""
    vy = open(os.path.join(_ROOT, "docker", "services", "vector.yaml"), encoding="utf-8").read()
    assert "/var/log/journal-remote:/var/log/journal-remote:ro" in vy, \
        "vector must bind-mount /var/log/journal-remote:ro (the receiver output the exec journalctl reads)"
