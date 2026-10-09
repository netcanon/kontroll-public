# Shared run-log helper for operator-run kontroll scripts (Layer 0 logging,
# docs/logging-architecture.md §3). Source it, then call `run_log_init <name>` once near the
# top of a script: from that point the script's stdout+stderr are tee'd to a timestamped log
# in an OPERATOR-writable dir (these scripts run as the operator, NOT the uid-1001 runner), and
# logs older than KONTROLL_RUNLOG_RETENTION_DAYS (default 30) are pruned. Gives a persistent
# "what ran, when, succeeded?" trail.
#
#   KONTROLL_RUN_LOG_DIR           override the dir (default ${XDG_STATE_HOME:-~/.local/state}/kontroll/runs)
#   KONTROLL_RUNLOG_RETENTION_DAYS prune age in days (default 30; empty/non-numeric -> 30, fail-closed)
#   RUN_LOG_FILE                   set by run_log_init -> this run's log path
#
# Secret-safety is the CALLER's responsibility — never echo a credential (no redaction here).
# Tee uses a process substitution; the final buffered lines can be lost if the shell exits
# abruptly — acceptable for an ops run-log (the durable record of intent + outcome, not a ledger).

run_log_init() {
  local name="${1:-run}"
  local dir="${KONTROLL_RUN_LOG_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/kontroll/runs}"
  mkdir -p "$dir" 2>/dev/null || return 0          # fail-soft: no dir -> no run-log, script proceeds
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_LOG_FILE="$dir/${name}-${ts}.log"
  : > "$RUN_LOG_FILE" 2>/dev/null || {           # fail-soft: unwritable (full/RO disk) -> no run-log
    echo "run-log: cannot write $RUN_LOG_FILE — continuing without a run-log" >&2; return 0; }
  exec > >(tee -a "$RUN_LOG_FILE") 2>&1            # tee all later output -> console + the log
  echo "# kontroll $name run $ts (pid $$)"
  # Retention: KONTROLL_RUNLOG_RETENTION_DAYS (default 30). FAIL-CLOSED — empty/non-numeric clamps to 30 so a
  # garbage value can never become a malformed `-mtime` (which would error, or worse match nothing).
  local days="${KONTROLL_RUNLOG_RETENTION_DAYS:-30}"
  case "$days" in '' | *[!0-9]*) days=30 ;; esac
  find "$dir" -name '*.log' -type f -mtime "+$days" -delete 2>/dev/null || true
}
