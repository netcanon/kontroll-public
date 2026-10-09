"""logging file_tail_ssh (S11) — the remote journald-over-SSH PULL method.

Codifies the three contracts that the design + the live bench established (local/s11-file-tail-ssh-bench-findings.md):

  1. GATED CUSTOM IMAGE — the stock timberio/vector image ships journalctl but NO ssh client (bench-verified
     2026-06-17), so file_tail_ssh's `exec ssh` source needs the thin kontroll/vector image (stock +
     openssh-client). It is built + selected (KONTROLL_VECTOR_IMAGE) ONLY when a class declares file_tail_ssh;
     every other instance keeps the STOCK pinned image. The Dockerfile FROM is pinned in LOCKSTEP with
     vector.yaml's default tag (a bump can't silently desync them).
  2. KEY-FILE INJECTION (the 3rd shape) — the read PRIVATE key is rendered from the logging_file_tail SOPS domain
     to a 0600 file and bind-mounted RO into Vector at the SAME path the descriptor's ssh `-i` references; an
     empty placeholder keeps the static file-bind valid (a missing source would be auto-created as a root DIR).
  3. FORCED-COMMAND READ KEY — the sender role authorizes the key locked to `journalctl -f -o json` with no-pty /
     no forwarding, so the key can run ONLY that read command (no shell, no arbitrary file read).

Text assertions on the shipped files — they fail loudly if a future edit drops the key mount, un-gates the
custom image, desyncs the pinned base tag, or loosens the forced command into a shell.
"""
import os

import pytest
import yaml

pytestmark = pytest.mark.unit

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _descriptor():
    return yaml.safe_load(_read("logging/file_tail_ssh.yml"))


def test_dockerfile_from_is_pinned_in_lockstep_with_vector_yaml_default():
    """The custom Vector image's FROM tag MUST equal docker/services/vector.yaml's
    `${KONTROLL_VECTOR_IMAGE:-<tag>}` default — they pin the SAME base. If a base-image bump touches only one,
    the gated custom image would build on a different Vector than the stock-image instances run, a silent skew.
    This drift-pin fails the moment they diverge."""
    dockerfile = _read("docker/vector-image/Dockerfile")
    from_line = next(ln for ln in dockerfile.splitlines() if ln.strip().startswith("FROM "))
    from_tag = from_line.split()[1]
    vy = _read("docker/services/vector.yaml")
    # the default after the `:-` in ${KONTROLL_VECTOR_IMAGE:-<default>}
    marker = "${KONTROLL_VECTOR_IMAGE:-"
    assert marker in vy, "vector.yaml image must be overridable via ${KONTROLL_VECTOR_IMAGE:-<stock default>}"
    default_tag = vy.split(marker, 1)[1].split("}", 1)[0].strip()
    assert from_tag == default_tag, \
        "Dockerfile FROM (%r) must match vector.yaml's stock default (%r) — keep them in lockstep" \
        % (from_tag, default_tag)


def test_dockerfile_runs_non_root_no_user_root():
    """The custom Vector image must NOT assert `USER root` — non-root is driven by the compose `user:` key (the
    universal switch covering BOTH the stock + custom image), so the gated image pinning root would undo it on the
    file_tail_ssh path (C12 promotion fix). Guards a silent revert to USER root in the custom image."""
    user_lines = [ln.strip() for ln in _read("docker/vector-image/Dockerfile").splitlines()
                  if ln.strip().startswith("USER ")]
    assert not any(ln in ("USER root", "USER 0", "USER 0:0") for ln in user_lines), \
        "the custom Vector image must not assert USER root (non-root via the compose user: key)"


def test_deploy_stack_renders_key_owned_by_the_vector_runtime_uid():
    """deploy-stack renders the file_tail_ssh key + its dir owned by the SAME uid Vector runs as in compose — SSH
    refuses a private key not owned by the running uid, so a uid mismatch would silently blank the exec-ssh stream.
    Guards the key render uid drifting from the compose `user:` uid (C12 non-root)."""
    uid = str(yaml.safe_load(_read("docker/services/vector.yaml"))["services"]["vector"]["user"]).split(":")[0]
    ds = _read("ansible/playbooks/deploy-stack.yml")
    region = ds[ds.index("file_tail_ssh.key"):ds.index("file_tail_ssh.key") + 800]
    assert ('owner: "%s"' % uid) in region, \
        "the key render must own the key as the Vector compose uid %s (SSH demands key owner == running uid)" % uid


def test_dockerfile_adds_openssh_client_the_one_missing_piece():
    """The custom image's ONLY addition is openssh-client — the one thing the stock image lacks for the exec-ssh
    source (the bench finding). Guards the image growing scope (it must stay a thin one-package layer) or the
    package being dropped (the exec source would fail `ssh: not found` again)."""
    dockerfile = _read("docker/vector-image/Dockerfile")
    assert "openssh-client" in dockerfile, "the custom Vector image must install openssh-client (bench-required)"


def test_vector_image_is_env_overridable_defaulting_to_stock():
    """vector.yaml's image is `${KONTROLL_VECTOR_IMAGE:-timberio/vector:...}` — the stock pinned tag is the
    DEFAULT, overridden by deploy-stack to kontroll/vector ONLY when file_tail_ssh is declared. Guards a
    regression that hardcodes the custom image for everyone (forcing a locally-built Vector on instances that
    don't use SSH-pull — the convention this design deliberately preserved)."""
    vy = _read("docker/services/vector.yaml")
    assert "image: ${KONTROLL_VECTOR_IMAGE:-timberio/vector:" in vy, \
        "vector.yaml image must default to the stock pinned tag and be env-overridable"


def test_vector_bind_mounts_the_read_key_ro_at_the_descriptor_path():
    """vector.yaml bind-mounts the file_tail_ssh read key READ-ONLY, and the mount TARGET equals the path the
    descriptor's ssh `-i` references — so the key Vector reads is exactly the key the exec source authenticates
    with (loop closed: deploy-stack renders -> this mount -> exec -i). RO: Vector reads the key, never writes it
    (C12). Guards the mount being dropped (ssh would have no identity) or the two paths drifting apart."""
    vy = _read("docker/services/vector.yaml")
    assert "/vector/file_tail_ssh.key:/etc/vector-keys/file_tail_ssh:ro" in vy, \
        "vector must bind-mount the rendered key RO at /etc/vector-keys/file_tail_ssh"
    cmd = _descriptor()["source"]["command"]
    key_path = cmd[cmd.index("-i") + 1]
    assert key_path == "/etc/vector-keys/file_tail_ssh", \
        "the descriptor ssh -i path (%r) must match the vector.yaml mount target" % key_path


def test_deploy_stack_gates_the_custom_image_and_renders_the_key():
    """deploy-stack builds kontroll/vector + sets KONTROLL_VECTOR_IMAGE + renders the read key ALL gated on the
    file_tail_ssh declaration (the find on file_tail_ssh_*.generated.yaml). The key render is no_log + 0600 from
    the logging_file_tail domain, with an empty placeholder (force:false, never clobber a real key) so the
    file-bind always resolves. Guards: an un-gated always-custom build, a leaked key (missing no_log), or a
    missing placeholder (Docker auto-creating a root DIR at the bind source — the G9 trap)."""
    ds = _read("ansible/playbooks/deploy-stack.yml")
    assert "patterns: \"file_tail_ssh_*.generated.yaml\"" in ds, "must detect file_tail_ssh from the generated tree"
    assert "register: _file_tail_ssh_decls" in ds, "the detection registers _file_tail_ssh_decls"
    assert "name: kontroll/vector:latest" in ds, "must build the custom Vector image"
    assert "KONTROLL_VECTOR_IMAGE=kontroll/vector:latest" in ds, "must point compose at the custom image in .env"
    assert "_file_tail_ssh_decls.matched" in ds, "the image build + .env var must be GATED on the declaration"
    assert "logging_file_tail.sops.yml" in ds, "must decrypt the logging_file_tail domain for the key"
    assert "ssh_private_key" in ds, "must render the ssh_private_key field to the key file"
    # the render task must be no_log and the placeholder must never clobber a real key
    render_idx = ds.index("logging_file_tail.sops.yml")
    assert "no_log: true" in ds[render_idx:render_idx + 1200], "the key render task must be no_log (no secret leak)"
    assert "force: false" in ds, "the empty placeholder must use force:false so it never clobbers a rendered key"


def test_exec_ssh_pins_host_key_no_tofu():
    """The exec-ssh source uses StrictHostKeyChecking=yes (NO accept-new TOFU) reading a READ-ONLY,
    operator-pinned UserKnownHostsFile under /etc/vector-keys — so a first-connect mgmt-VLAN MITM cannot silently
    substitute a target's host key (C12 residual 2). Guards a regression back to accept-new or to the writable
    /var/lib/vector path (which re-opens TOFU)."""
    cmd = _descriptor()["source"]["command"]
    assert "StrictHostKeyChecking=yes" in cmd, "must pin the host key (StrictHostKeyChecking=yes, no accept-new)"
    assert "accept-new" not in " ".join(cmd), "the accept-new TOFU must be gone"
    khf = next(p.split("=", 1)[1] for p in cmd if p.startswith("UserKnownHostsFile="))
    assert khf == "/etc/vector-keys/file_tail_known_hosts", \
        "known_hosts must be the RO operator-pinned file, not the writable vector-data path (got %r)" % khf


def test_vector_bind_mounts_the_pinned_known_hosts_ro():
    """vector.yaml RO-binds the assembled known_hosts at the path the exec ssh reads — closing the loop
    deploy-stack(assemble) -> mount -> ssh UserKnownHostsFile. Guards the mount being dropped or drifting."""
    vy = _read("docker/services/vector.yaml")
    assert "/vector/file_tail_known_hosts:/etc/vector-keys/file_tail_known_hosts:ro" in vy, \
        "vector must RO-bind the assembled known_hosts at the descriptor's UserKnownHostsFile path"


def test_deploy_stack_assembles_known_hosts_always_written():
    """deploy-stack assembles the pinned known_hosts from device_trust.<key>.ssh_known_hosts_file and ALWAYS
    writes it (empty when none pinned) so the static bind resolves to a FILE (G9) and the on-disk pin set tracks
    the current instance decisions. PUBLIC host keys (no secret) -> 0644, no no_log. Guards the assemble being
    dropped or the var name drifting from the descriptor."""
    ds = _read("ansible/playbooks/deploy-stack.yml")
    assert "file_tail_known_hosts" in ds, "deploy-stack must assemble the pinned known_hosts file"
    assert "ssh_known_hosts_file" in ds, "the assemble must read device_trust.<key>.ssh_known_hosts_file"
    assert "_known_hosts_paths" in ds, "the assemble must iterate the _known_hosts_paths var (sibling of _ca_paths)"


def test_sender_role_forces_journalctl_json_with_no_shell():
    """The forced-command read key is locked to `journalctl -f -o json` (NDJSON for Vector's full-fidelity decode)
    with no-pty + no forwarding, so the key can run ONLY that read command — never an interactive shell, never an
    arbitrary file read (the tightest possible grant). Guards the forced command being loosened back to a shell
    or the no-pty/forwarding restrictions being dropped (which would turn the read key into a shell key)."""
    defaults = yaml.safe_load(_read("ansible/roles/logging_file_tail_ssh/defaults/main.yml"))
    forced = defaults["logging_tail_command"]
    assert forced == "journalctl -f -o json", \
        "the forced command must be `journalctl -f -o json` (NDJSON for Vector), got %r" % forced
    main = _read("ansible/roles/logging_file_tail_ssh/tasks/main.yml")
    assert 'command="{{ logging_tail_command }}"' in main, "the authorized_keys line must FORCE the command"
    for opt in ("no-pty", "no-port-forwarding", "no-agent-forwarding", "no-X11-forwarding"):
        assert opt in main, "the forced-command key must carry %s (no shell, no tunnels)" % opt
