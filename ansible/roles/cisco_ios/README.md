# role: cisco_ios

Device-class role for the Catalyst 9300-24UXM (current core switch).

## Entrypoints (tasks_from)

| Entrypoint | Purpose | Blast radius |
|---|---|---|
| `backup` | `show running-config` → repo capture | none (read-only) |
| `main` (TODO) | apply intended config (idempotent `ios_config`) | this device / VLAN |

## Connection

`network_cli` via `cisco.ios.ios` (see `group_vars/core_switch.yml`). Creds
from `secrets/network.sops.yml`.

## Modularity note

Self-contained. The core switch swap at cutover means activating the
`routeros` role instead of this one (flip membership in `inventory/hosts.yml`);
this role is left in place for the warm-rollback window, then retired.
