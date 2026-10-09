#!/usr/bin/env bash
# Live smoke gate — one command to assert the fleet responds, post-deploy or from a webhook.
#
# ansible/playbooks/ping.yml IS the gate already: a TCP reachability probe from the control
# node, then each class's read-only `check` (real protocol/creds liveness), then an honest
# pass/fail assertion (a reachable host whose check errors fails the run; a down host is
# tolerated). It runs as the 'ping-fleet' Semaphore template. This script FORMALIZES it as a
# callable, pollable, queryable gate: it triggers the template, polls to completion, and
# reports PASS/FAIL with the task id — results stay queryable via the Semaphore task API
# (GET /api/project/<p>/tasks/<id>[/output]). Correlate by the kontroll_run_id in the output.
#
# Usage:   scripts/run-smoke-gate.sh
# Exit:    0 = PASS, 1 = FAIL/timeout, 2 = misconfigured (no such template)
# Env:     SEMAPHORE_URL (default http://localhost:3001)  PROJECT_ID (1)
#          SMOKE_TEMPLATE (default ping-fleet)            SEMAPHORE_ADMIN (admin)
#          SEMAPHORE_ADMIN_PASSWORD (else decrypted from instance/secrets/semaphore.sops.yml —
#          needs the age key; a remote webhook handler should pass it in the env instead)
set -euo pipefail
cd "$(dirname "$0")/.."
# Layer 0: tee this run to a persistent, 30-day-pruned log (docs/logging-architecture.md §3).
if [ -f scripts/lib/run-log.sh ]; then . scripts/lib/run-log.sh; run_log_init "smoke-gate"; fi

URL="${SEMAPHORE_URL:-http://localhost:3001}/api"
PROJECT="${PROJECT_ID:-1}"
TEMPLATE_NAME="${SMOKE_TEMPLATE:-ping-fleet}"
ADMIN="${SEMAPHORE_ADMIN:-admin}"
PW="${SEMAPHORE_ADMIN_PASSWORD:-}"
if [ -z "$PW" ]; then
  PW=$(sops -d instance/secrets/semaphore.sops.yml \
       | python3 -c "import sys,yaml;print(yaml.safe_load(sys.stdin)['semaphore_admin_password'])")
fi

J=$(mktemp); trap 'rm -f "$J"' EXIT
# Send the login body via STDIN (--data @-), never as a -d argv element — otherwise the
# password is world-readable in `ps`/`/proc/<pid>/cmdline` for the request's lifetime.
curl -fsS -c "$J" -H 'Content-Type: application/json' --data @- "$URL/auth/login" >/dev/null <<JSON
{"auth":"$ADMIN","password":"$PW"}
JSON

# Resolve the template id IN python (first match) — no `| head -1`, which under `set -o
# pipefail` would SIGPIPE python and abort the script if two templates shared the name.
TID=$(curl -fsS -b "$J" "$URL/project/$PROJECT/templates" \
      | python3 -c "import sys,json;ids=[t['id'] for t in json.load(sys.stdin) if t['name']=='$TEMPLATE_NAME'];print(ids[0] if ids else '')")
[ -n "$TID" ] || { echo "smoke-gate: no template named '$TEMPLATE_NAME' in project $PROJECT" >&2; exit 2; }

echo "smoke-gate: triggering '$TEMPLATE_NAME' (template $TID)…"
TASK=$(curl -fsS -b "$J" -H 'Content-Type: application/json' \
       -d "{\"template_id\":$TID,\"project_id\":$PROJECT}" "$URL/project/$PROJECT/tasks" \
       | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "smoke-gate: task $TASK started — query: $URL/project/$PROJECT/tasks/$TASK"

for _ in $(seq 1 80); do
  S=$(curl -fsS -b "$J" "$URL/project/$PROJECT/tasks/$TASK" \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('status','?'))")
  case "$S" in
    success) echo "smoke-gate: PASS (task $TASK)"; exit 0;;
    error|stopped)
      echo "smoke-gate: FAIL ($S, task $TASK) — tail of output:" >&2
      curl -fsS -b "$J" "$URL/project/$PROJECT/tasks/$TASK/output" \
        | python3 -c "import sys,json;[print(o.get('output','')) for o in json.load(sys.stdin)]" | tail -25 >&2
      exit 1;;
  esac
  sleep 3
done
echo "smoke-gate: TIMEOUT waiting on task $TASK" >&2
exit 1
