# role: fortigate

Device-class role for the **FortiGate / FortiOS** firewall (module `fortigate`,
group `edge_firewall` — current edge). Collection: `fortinet.fortios`. Secrets:
`network` domain. **High blast radius — this is the live edge.**

## Entrypoints (`tasks_from`)

`check` and `backup` are now **thin wrappers over the generic `api` backend**
([roles/backend_api](../backend_api/README.md)) with `backend_api_recipe: fortios` —
no vendor module at capture time. This proved the api backend captures a real REST
device faithfully (byte-identical full-configuration; see backend_api README).

| Entrypoint | Purpose | Blast radius |
|---|---|---|
| `check` | liveness via the `fortios` recipe (`/api/v2/monitor/system/status`) | none |
| `backup` | full-configuration capture via the `fortios` recipe (read-only GET) | none |
| `main` (TODO) | apply firewall/policy config | **WAN / all LAN** — `--check` first |

## Connection
Backup/check run as localhost-delegated REST `uri` (the api backend); the group's
`httpapi` connection (`group_vars/edge_firewall.yml`) remains for future actuation
via `fortinet.fortios`. Token in `secrets/network.sops.yml` (`fortios_api_token`).

> **Backup: implemented** (`backup_capable: true`) — full-configuration via the
> FortiOS backup API (api backend, `fortios` recipe), `no_log` (request token +
> response config are secret-bearing). Retires at cutover (swap to `opnsense`).
