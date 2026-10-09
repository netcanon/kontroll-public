"""The host-floor installers are nixflavor-agnostic — package-manager + init-system dispatch, not apt-only.

WHY (the failure these guard): the compose-native architecture pushes the toolchain into the installer IMAGE, so the
HOST floor is just "Docker + git" — but the two host-floor scripts (install-prereqs.sh, host-systemd.sh) were
hard-wired to apt/Debian, which blocks a Fedora/RHEL/Rocky/Arch/openSUSE operator at step one (the live Rung-2
dogfood confirmed the dominant non-portability is here). These pins assert the scripts dispatch via the shared
scripts/lib/pkg.sh helper (apt/dnf/zypper/pacman + a get.docker.com universal fallback), never a bare unguarded
`apt-get`, and that the sops download arch is derived from the machine (not a hardcoded amd64) — so a future edit
that re-hardcodes apt or amd64 fails CI. The dispatch is explicitly NOT install-gating (it runs before the offline
never-brick generators), so adding network-using, distro-branching logic here is BRICK-1-neutral.
"""
import os
import re

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def test_pkg_lib_covers_the_four_package_managers():
    """scripts/lib/pkg.sh must detect + dispatch apt, dnf, zypper, AND pacman (the mainstream Linux PMs) and expose
    the helpers the floor scripts source. Guards a dispatch that silently omits a PM (that distro's operator falls
    through to the fail-closed 'install manually' path with no automation)."""
    pkg = _read("scripts/lib/pkg.sh")
    for fn in ("pkg_detect", "pkg_install", "svc_enable_now", "arch_deb"):
        assert "%s()" % fn in pkg, "pkg.sh must define %s()" % fn
    for pm in ("apt", "dnf", "zypper", "pacman"):
        assert re.search(r"\b%s\b" % pm, pkg), "pkg.sh must dispatch the %s package manager" % pm
    assert "get.docker.com" not in pkg  # the universal Docker installer belongs in install-prereqs, not the lib


def test_install_prereqs_dispatches_and_does_not_hardcode_apt():
    """install-prereqs.sh must source pkg.sh, install the floor via pkg_install (not a bare `apt-get install`),
    enable Docker via svc_enable_now (init-system-gated), provide the get.docker.com universal Docker path for
    non-apt distros, and verify `docker info`. Guards a regression back to apt-only (the live BLOCKER)."""
    s = _read("scripts/install-prereqs.sh")
    assert "lib/pkg.sh" in s, "must source the shared pkg dispatch"
    assert "pkg_install git tar curl" in s, "the host floor must install via pkg_install, not bare apt-get"
    assert "svc_enable_now docker" in s, "Docker must start via the init-system-gated helper, not a bare systemctl"
    assert "get.docker.com" in s, "non-apt distros need the universal Docker installer"
    assert "docker info" in s, "the script must verify the daemon is actually up (degrade with a hint, not silently)"
    # the apt deb822 path must remain (it must match the image + deploy-stack), but only on the apt branch
    assert "/etc/apt/sources.list.d/docker.sources" in s and '"$PKG_MGR" = apt' in s
    # no UNGUARDED bare `apt-get install` as a floor path — every apt-get install is inside an apt branch or pkg_install
    assert "\napt-get install" not in s, "no top-level bare apt-get install (must go through pkg_install / apt branch)"


def test_host_systemd_dispatches_via_pkg_lib():
    """host-systemd.sh (the OPTIONAL Proxmox/logrotate residual) must also dispatch via pkg.sh — same apt-only
    BLOCKER otherwise for a non-Debian operator who follows the '(optional) host-systemd.sh' doc line."""
    s = _read("scripts/host-systemd.sh")
    assert "lib/pkg.sh" in s
    assert "pkg_install qemu-guest-agent" in s and "pkg_install logrotate" in s
    assert "\napt-get install" not in s, "no bare apt-get install (must go through pkg_install)"


def test_bootstrap_sops_url_is_arch_derived():
    """bootstrap.yml's host-direct sops download must derive the arch from ansible_architecture, not hardcode
    `.linux.amd64` — else an aarch64 control node on the host-direct path downloads an x86 binary that won't run."""
    b = _read("ansible/playbooks/bootstrap.yml")
    assert ".linux.amd64" not in b, "the sops URL must not hardcode amd64"
    assert "ansible_architecture" in b, "the sops arch must come from the gathered fact"
