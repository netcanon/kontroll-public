#!/usr/bin/env bash
# Stage 0 — the irreducible prerequisite. Thin shim: delegates to scripts/install-prereqs.sh, the ONE
# system-dependency installer (ansible, git, Docker + compose, python, acl, openssl). Kept so the documented
# `./bootstrap.sh` keeps working; the logic lives in scripts/install-prereqs.sh now (it also installs Docker,
# which this script historically did not — the whole stack runs in compose). Idempotent. See docs/SETUP.md §1.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec sudo bash "${HERE}/scripts/install-prereqs.sh" "$@"
