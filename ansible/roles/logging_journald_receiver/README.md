# roles/logging_journald_receiver

**Collector-side** receiver for the `journald_remote` logging method — the counterpart to the **sender** role
[`logging_journald_remote`](../logging_journald_remote/README.md) (which runs on each remote host). Installs
`systemd-journal-remote` on the **control node** and runs it as a small service bound to the **management IP**
`:19532` only; uploaded journals land in `/var/log/journal-remote/` where Vector's `exec` journalctl source
([`logging/journald_remote.yml`](../../../logging/journald_remote.yml)) reads them and ships to Loki.

```
# Access chain used:   runs ON the control node (localhost) — a host package + a mgmt-bound systemd service
# May break:           nothing on the lab — a mgmt-bound :19532 receiver on the control node only
# Fallback required:   no
# Blast radius:        this control node (a host package + a :19532 service + a journal dir; reversible)
```

## Why this shape (bench-proven — `local/s10-journald-receiver-bench-findings.md`)

`systemd-journal-upload` streams the **binary journal export format** (`FIELD=value` lines), **not JSON**, so a
Vector `http_server` source can't field-parse it (the reverted PR #12/#13: `codec json` → **0 events**). The native
receiver that speaks the upload protocol is `systemd-journal-remote`, which writes real `.journal` files. A Vector
**`journald` source** can't read them either — it filters to the current boot `+0` and **drops remote journals**
(whose boot differs), and an explicit `current_boot_only: false` is rejected on systemd 250-257. So the method reads
them with an **`exec` `journalctl --directory=/var/log/journal-remote -o json -f`** source (all boots, version-robust,
clean NDJSON) — **LIVE-PROVEN end-to-end to Loki**.

- **Bound to the mgmt IP only** via `--listen-http={{ logging_collector_host }}:19532` — a **specific IP**, never a
  bare port / `0.0.0.0` (SECURITY.md C3/C12; live-verified the IP binds that interface alone). The role **asserts**
  `logging_collector_host` is set, so it can never silently fall back to all-interfaces.
- **Separate dir** `/var/log/journal-remote` (NOT under `/var/log/journal`) so the `internal_journald` source never
  double-ingests the uploads.
- Uses a **custom service unit** (`kontroll-journal-remote.service`), not the packaged `systemd-journal-remote.socket`
  (which was flaky on the bench).

## How it runs

Provisioned automatically by `deploy-stack.yml` when **a class declares `journald_remote`** (gated on the rendered
`docker/vector/generated/journald_remote_*.generated.yaml`) and `vector` is in `stack_services` — `logging_collector_host`
is the instance mgmt IP. Manually: `ansible-playbook ... -e logging_collector_host=<mgmt-ip>` against localhost.

## Entrypoints

| `tasks_from:` | Does |
|---|---|
| `main` (default) | Install systemd-journal-remote + the mgmt-bound `kontroll-journal-remote.service` + the output dir. Idempotent, `--check`-safe. |
| `backup` | Capture the current receiver unit as the rollback reference (read-only slurp → control-side). |

## Knobs

| var | default | meaning |
|---|---|---|
| `logging_collector_host` | *(required — asserted)* | the mgmt IP to bind `:19532` to (never `0.0.0.0`) |
| `logging_journald_upload_port` | `19532` | the receiver port (matches the sender's `logging_journald_upload_port`) |

## Privilege (C12 — root half closed)

The receiver runs as the **non-root `systemd-journal-remote` user** (`Group=systemd-journal`, `NoNewPrivileges`,
`ProtectSystem=strict`), so this network-facing **unauthenticated** listener no longer runs root. Its `2750`
output dir is `group=systemd-journal`, so Vector reads the uploaded journals via the **same supplementary gid** it
reads host journald by (one grant). The listener being **unauthenticated** is the separate deferred residual
(C12 residual 4 — TLS journal-upload), not closed here. Pinned by `tests/unit/test_journald_receiver.py`.

See also: [`logging/journald_remote.yml`](../../../logging/journald_remote.yml),
[`roles/logging_journald_remote`](../logging_journald_remote/README.md),
[`docs/logging-architecture.md`](../../../docs/logging-architecture.md).
