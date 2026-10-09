# role: openwrt

Device-class role for the **OpenWrt AP** (module `openwrt`, group `wireless_ap`
— Belkin RT3200). **No collection** — raw SSH via `ansible.builtin.raw`.
Secrets: `network` domain.

## Entrypoints (`tasks_from`)

| Entrypoint | Purpose | Blast radius |
|---|---|---|
| `backup` | `uci export` capture (read-only) | none |
| `main` (TODO) | apply uci config | this AP / SSIDs |

## Connection
Raw SSH (`ansible_user: root`). See `group_vars/wireless_ap.yml`.

> **Backup: implemented** (`backup_capable: true`) — `uci export` via raw SSH,
> `no_log` (carries wireless PSKs).
