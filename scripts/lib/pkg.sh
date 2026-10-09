#!/usr/bin/env sh
# scripts/lib/pkg.sh — package-manager + init-system dispatch for the HOST FLOOR (nixflavor-agnostic).
#
# WHY: the compose-native architecture pushes ansible/sops/age/collections into the EPHEMERAL installer IMAGE, so
# the host only needs "Docker + git". The image is intentionally Debian internally — but the HOST an operator runs
# the docs on can be ANY mainstream Linux. The two host-floor scripts (install-prereqs.sh, host-systemd.sh) were
# apt-only, which blocked a Fedora/RHEL/Rocky/Arch/openSUSE operator at step one. This sourced helper detects the
# package manager + init system and dispatches, so the floor installs everywhere with one code path.
#
# NOT install-gating: this runs BEFORE the never-brick generators (gen-requirements/install-collections) and is
# allowed to reach the network (it bootstraps Docker). It never touches the offline/fail-closed install seam, so
# adding network-using, distro-branching logic here does not weaken the BRICK-1 invariant.
#
# POSIX sh (no bashisms) so it sources cleanly under sh or bash. Sets PKG_MGR; provides pkg_refresh / pkg_install /
# svc_enable_now / arch_deb.

# Detect the system package manager → PKG_MGR (apt|dnf|zypper|pacman|unknown). dnf is preferred over its yum alias.
pkg_detect() {
  if command -v apt-get >/dev/null 2>&1; then PKG_MGR=apt
  elif command -v dnf >/dev/null 2>&1; then PKG_MGR=dnf
  elif command -v zypper >/dev/null 2>&1; then PKG_MGR=zypper
  elif command -v pacman >/dev/null 2>&1; then PKG_MGR=pacman
  else PKG_MGR=unknown
  fi
  echo "$PKG_MGR"
}

# Refresh the package index (best-effort; a stale index is not fatal for our floor packages).
pkg_refresh() {
  [ -n "${PKG_MGR:-}" ] || PKG_MGR="$(pkg_detect)"
  case "$PKG_MGR" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq ;;
    dnf)    dnf -q makecache >/dev/null 2>&1 || true ;;
    zypper) zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null 2>&1 || true ;;
    pacman) pacman -Sy --noconfirm >/dev/null 2>&1 || true ;;
  esac
}

# pkg_install <pkg>… — install packages non-interactively via the detected PM. Returns non-zero (with a clear
# message) when no supported PM exists, so the caller can fail closed with a manual-install hint.
pkg_install() {
  [ "$#" -gt 0 ] || return 0
  [ -n "${PKG_MGR:-}" ] || PKG_MGR="$(pkg_detect)"
  case "$PKG_MGR" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf)    dnf install -y -q "$@" ;;
    zypper) zypper --non-interactive install -y "$@" ;;
    pacman) pacman -S --needed --noconfirm "$@" ;;
    *) echo "no supported package manager (apt/dnf/zypper/pacman) — install manually: $*" >&2; return 1 ;;
  esac
}

# svc_enable_now <service> — enable+start a service across init systems, degrading gracefully on a non-systemd /
# non-OpenRC host instead of leaving the operator with a silently-unstarted daemon. Never aborts the caller.
svc_enable_now() {
  _svc="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "$_svc" >/dev/null 2>&1 || true
  elif command -v rc-update >/dev/null 2>&1; then
    rc-update add "$_svc" default >/dev/null 2>&1 || true
    rc-service "$_svc" start >/dev/null 2>&1 || true
  else
    echo "    no systemctl/rc-update found — start '$_svc' via your init system." >&2
  fi
}

# arch_deb — the Docker/sops release naming for this machine's architecture, derived from `uname -m` (portable;
# `dpkg --print-architecture` only exists on Debian). amd64/arm64/armhf cover the realistic control-node set.
arch_deb() {
  case "$(uname -m)" in
    x86_64|amd64)   echo amd64 ;;
    aarch64|arm64)  echo arm64 ;;
    armv7l|armhf)   echo armhf ;;
    *)              uname -m ;;
  esac
}
