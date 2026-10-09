# role: proxmox

Device-class role for **Proxmox VE hypervisors** (module `proxmox`, group
`hypervisors`). Collection: `community.proxmox`. Secrets: `proxmox` domain.

## Entrypoints (`tasks_from`)

| Entrypoint | Purpose | Blast radius |
|---|---|---|
| `backup` | capture guest + node config (read-only) | none |
| `main` (TODO) | apply intended VM/host config | this node / cluster |

## Connection
SSH (`ansible_user: root`) for host tasks; `community.proxmox` API token (from
`secrets/proxmox.sops.yml`) for cluster/VM tasks. See `group_vars/hypervisors.yml`.

> **Backup: implemented** (`backup_capable: true`) — guest `.conf` + node
> network/storage via SSH, `no_log`. Config capture only (not VM-image/vzdump).
