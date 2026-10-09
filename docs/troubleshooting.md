# Troubleshooting runbook — where each signal lives + how to read it

The operability companion to [logging-architecture.md](logging-architecture.md). When something looks wrong,
this tells you **which label each kontroll surface lands under**, the **queries** to run, and — crucially — how
to keep debugging **when the observability stack itself is down** (the degrade path). All of this is also a pane
in the Grafana **kontroll — Logs** dashboard (`dashboards/grafana/dashboards/logs.json`); the queries here and
the dashboard panels are kept in sync on purpose.

> Conventions: every log line carries the canonical, non-secret label set `{source, host, service, level,
> run_id, device}` (C12). `source` splits **internal** (the stack's own logs) from **capability** (device/service
> logs ingested via the logging capability). `run_id` correlates one operation across surfaces and is set on
> **internal** streams only (device logs are not part of a kontroll run).

## 1. Where each signal lives (the label map)

| Surface | `source` | `service` | Notes |
|---|---|---|---|
| Container stdout/stderr (every stack service) | `internal` | the **container name** (`vector`, `loki`, `semaphore`, `api`, …) | from the Docker source |
| Host journald (systemd) | `internal` | the **unit** (`docker.service`, `sshd.service`, …), else `host` | persistent journal |
| API audit (who/when/what on the API) | `internal` | `api-audit` | kept **90d**; never the credential |
| GUI audit (onboard-GUI actions) | `internal` | `gui-audit` | kept **90d** |
| Ansible run-log (playbook runs) | `internal` | `ansible` | carries the `run_id` of the run |
| Script run-logs (CLI helpers) | `internal` | the **script name**, else `script` | from `~/.local/state/kontroll/runs` |
| A device/service's own logs (logging capability) | `capability` | the **method** (`syslog_push`, …) | + `device=<module key>` (e.g. `cisco_ios`) |

## 2. Common LogQL queries (Grafana → Explore → Loki, or `logcli`)

```logql
# Everything from one operation, greppable by its correlation id (internal only):
{source="internal", run_id="20260616T143000Z"}

# A specific surface (audit trail kept 90d):
{source="internal", service=~"api-audit|gui-audit"}

# Anything wrong, across the whole stack:
{source=~".+", level=~"error|warn"}

# One device class's ingested logs (the logging capability):
{source="capability", device="cisco_ios"}

# Free-text body search (a |~ filter — a query, never a label, so no cardinality cost):
{source="internal"} |~ "(?i)backup.*fail|captured nothing"

# Volume of a chatty emitter (sizing-lever input; pairs with the dashboard "Top services" panel):
topk(10, sum by (service) (count_over_time({source="internal"} [1h])))
```

## 3. The degrade path — debugging when Loki/Vector is down

Observability must survive an observability outage. Loki or Vector being down loses log **shipping**, never the
source logs — every surface persists locally and is readable without the stack. Per the access-chain header in
`docker/services/vector.yaml` ("Fallback required: no … degrade to `docker logs`/journalctl/the flat audit files"):

| You want… | When the stack is up | When Loki/Vector is down |
|---|---|---|
| A container's logs | the `internal` stream by container name | `docker logs <name>` (bounded by daemon.json `max-size 10m ×5`) |
| Host/systemd logs | the journald `internal` stream | `journalctl -u <unit>` on the control VM |
| API audit | `{service="api-audit"}` | the flat TSV at `/var/lib/kontroll/api/audit/` |
| GUI audit | `{service="gui-audit"}` | the flat TSV at `/var/lib/kontroll/onboard-gui/audit/` (M11 — off the `/repo` code/propose clone) |
| Ansible run-log | `{service="ansible"}` | the flat log at `/var/lib/kontroll/ansible-log/` |
| Script run-logs | `{service=<script>}` | `~/.local/state/kontroll/runs/` |

Bring the stack back: `docker compose ... up -d loki vector` (or re-run `deploy-stack.yml` with `loki`/`vector`
in `stack_services`). Vector resumes from its on-disk checkpoint (the `vector-data` volume), so a restart
re-ships from where it stopped rather than re-reading everything.

## 4. Quick checks

- **No logs in Grafana at all** → confirm the Loki datasource provisioned (`uid: loki`); confirm Vector is
  Up and shipping (`docker logs vector | grep -i "Listening\|Healthcheck"`); confirm Loki `/ready`
  (`curl -s ${KONTROLL_MGMT_IP}:3100/ready`).
- **A device's syslog never arrives** (`{source="capability"}` empty) → confirm `docker/services/vector.yaml`
  publishes the mgmt-bound `:5514`, the device is configured to ship there (the `logging_syslog_push` wiring
  role), and the device can reach the collector on the mgmt VLAN.
- **Disk filling** → metrics are bounded by `PROM_RETENTION_SIZE`/`_TIME`; logs by `LOKI_RETENTION_PERIOD`
  (+ per-stream tiers); see the storage paradigm
  ([docs/reviews/2026-06-16-storage-logging/99-synthesis.md](reviews/2026-06-16-storage-logging/99-synthesis.md)).

## See also
- [logging-architecture.md](logging-architecture.md) — the layered design + the degrade-path source of truth
- [observability/logging-capability-vector.md](observability/logging-capability-vector.md) — the logging capability
- [../SECURITY.md](../SECURITY.md) **C12** — logs are a secret surface (label hygiene, mgmt-only, at-rest)
- `dashboards/grafana/dashboards/logs.json` — the same signals as a Grafana pane
