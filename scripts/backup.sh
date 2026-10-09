#!/usr/bin/env bash
# OPTIONAL offsite backup of a kontroll INSTANCE to a PLUGGABLE remote.
#
# The instance is the source of truth (docs/local-source-of-truth.md); this is a
# nice-to-have disaster-recovery copy, NEVER required to operate. The remote is any
# git target configured as a git remote on the working tree — git is just the
# transport. Each backup target gets its OWN strictly-scoped, single-repo write
# credential (e.g. a GitHub deploy key registered on only that repo, IdentitiesOnly
# pinned) so a backup remote can touch ONLY its own repo — never any other (SECURITY.md).
#
# Pushes the full instance (code + state). To restore: clone the backup, re-provision
# the age keys, run deploy-stack. (A non-git / tarball snapshot of just the
# state-manifest paths is the other DR mode — see docs/local-source-of-truth.md.)
#
# Targets (pluggable, multi-remote), resolved in order:
#   explicit args  >  instance/instance.yml `backup_remotes`  >  $KONTROLL_BACKUP_REMOTE  >  'backup'
# Usage:  scripts/backup.sh [<remote> ...]
set -euo pipefail
cd "$(dirname "$0")/.."
# Layer 0: tee this run to a persistent, 30-day-pruned log (docs/logging-architecture.md §3).
if [ -f scripts/lib/run-log.sh ]; then . scripts/lib/run-log.sh; run_log_init "backup"; fi

REMOTES=()
if [ "$#" -ge 1 ]; then
  REMOTES=("$@")
elif [ -f instance/instance.yml ] && command -v python3 >/dev/null 2>&1; then
  mapfile -t REMOTES < <(python3 -c 'import yaml; print("\n".join(yaml.safe_load(open("instance/instance.yml")).get("backup_remotes") or []))' 2>/dev/null || true)
fi
[ "${#REMOTES[@]}" -eq 0 ] && REMOTES=("${KONTROLL_BACKUP_REMOTE:-backup}")

HEAD="$(git rev-parse --short HEAD)"
rc=0
for REMOTE in "${REMOTES[@]}"; do
  if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
    echo "skip '$REMOTE' — not a configured remote (optional; the instance is unaffected)."
    continue
  fi
  echo "Backing up the instance (code+state @ $HEAD) to '$REMOTE'…"
  # Normal (fast-forward) push: the instance's history is authoritative and the backup
  # is written only from here, so it never diverges. If it ever rejects (history
  # rewritten), resolve deliberately — don't blindly --force a DR copy.
  if git push "$REMOTE" HEAD:refs/heads/main; then
    echo "  done — offsite copy at $(git remote get-url "$REMOTE")."
  else
    echo "  ! push to '$REMOTE' failed (the instance is unaffected)." >&2; rc=1
  fi
done
exit "$rc"
