#!/usr/bin/env bash
# Non-destructive code update for a kontroll INSTANCE.
#
# The instance is the source of truth (docs/local-source-of-truth.md). This pulls
# PRODUCT-CODE updates from an upstream remote and MERGES them, PRESERVING instance
# state — onboarded hosts, encrypted secrets, the fleet selection, dashboards. That is
# the whole point of Phase B: never `git reset --hard` (which would clobber the
# operator's local state commits). Code and state live in DISJOINT files
# (config/state-manifest.yml), so the merge is normally conflict-free; a genuine
# conflict means a *code* file was edited locally — surfaced, never silently lost.
#
# Then it re-seeds the local canonical the running instance (Semaphore) reads, so the
# new code takes effect with no remote git at run time.
#
# This is the DEVELOPER-managed update path (a git-connected instance). The git-FREE
# operator update — code delivered via the runner image / a release bundle — is Phase C.
#
# Usage:  scripts/update.sh [<remote> [<branch>]]      # default: origin main
set -euo pipefail
REMOTE="${1:-origin}"; BRANCH="${2:-main}"
cd "$(dirname "$0")/.."
# Layer 0: tee this run to a persistent, 30-day-pruned log (docs/logging-architecture.md §3).
if [ -f scripts/lib/run-log.sh ]; then . scripts/lib/run-log.sh; run_log_init "update"; fi

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  echo "No '$REMOTE' remote — this instance has no upstream. Code updates come via the" >&2
  echo "runner image / release bundle (Phase C), not git. Nothing to do." >&2
  exit 0
fi

echo "==> Fetching ${REMOTE}/${BRANCH} (product code)…"
git fetch --quiet "$REMOTE" "$BRANCH"

before="$(git rev-parse HEAD)"
echo "==> Merging code updates, preserving instance state…"
if ! git merge --no-edit "${REMOTE}/${BRANCH}"; then
  echo "" >&2
  echo "!! Merge conflict — a CODE file was edited on this instance. Resolve it, then" >&2
  echo "   re-run. Instance STATE (inventory/secrets/fleet/dashboards) is never the" >&2
  echo "   cause: it lives in files upstream doesn't touch (config/state-manifest.yml)." >&2
  exit 1
fi

if [ "$(git rev-parse HEAD)" = "$before" ]; then
  echo "==> Already up to date."
fi

echo "==> Re-seeding the local canonical (what the instance runs)…"
if git remote get-url local >/dev/null 2>&1; then
  git push --quiet local HEAD:refs/heads/main
  echo "    Local canonical updated — Semaphore runs the new code on its next job."
else
  echo "    No 'local' remote yet — run: ansible-playbook ansible/playbooks/local-canonical.yml"
fi

echo "==> Done. If the enabled modules/collections changed, re-run bootstrap + rebuild the runner."
