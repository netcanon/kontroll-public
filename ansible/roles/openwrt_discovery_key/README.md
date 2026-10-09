# roles/openwrt_discovery_key

Device-side **wiring role** for the `dhcp_leases_openwrt` discovery method (the passive-discovery inbox, C18).
Authorizes the sweep's **read-only, forced-command** SSH key on an OpenWrt AP so
[`scripts/kontroll-discover.py`](../../../scripts/kontroll-discover.py) can read the AP's own dnsmasq lease file
(`cat /tmp/dhcp.leases`) — and **nothing else** — without an interactive shell. Registry descriptor:
[`discovery/dhcp_leases_openwrt.yml`](../../../discovery/dhcp_leases_openwrt.yml).

```
# Access chain used:   control node (mgmt VLAN) -> OpenWrt AP (SSH) authorizes a read-only forced-command key
# May break:           none — adds ONE authorized_keys line scoped to `cat /tmp/dhcp.leases` (no shell, no sudo)
# Fallback required:   no
# Blast radius:        this host (a restricted read-only key; reversible — remove the line)
```

## Scope (the two halves)

- This role is the **host (key) side**: it authorizes the sweep's read **public** key on the AP, **forced** to
  `cat /tmp/dhcp.leases` (`no-pty,no-*-forwarding` — no shell, no arbitrary file read). The matching **sweep side**
  is the `ssh_read` fetcher in [`scripts/kontroll-discover.py`](../../../scripts/kontroll-discover.py) (`ssh
  root@<host>` with **no client command** → the AP's forced command runs), authenticated with the **private** key
  the operator decrypts from the `network` SOPS domain (`openwrt_discovery_ssh_private_key`) to an ephemeral `0600`
  file at sweep time (there is **no** deploy-time provisioning — the sweep is on-demand). See
  [`discovery/README.md`](../../../discovery/README.md) § Extending for the worked export flow.
- A **DEDICATED** key — **never** the full-shell `ansible_ed25519` root key the fleet uses to run arbitrary Ansible
  against the AP ([`group_vars/wireless_ap.yml`](../../../instance/inventory/group_vars/wireless_ap.yml)). The whole
  point of the forced-command sibling pattern (like `logging_file_tail_ssh`) is a key that can run **only** the one
  read command.
- Gated on `openwrt_discovery_pubkey` — empty (the default) makes the role a safe **no-op**, so a play that
  references it never fails for want of a key.

## How it runs

```bash
ansible-playbook -i instance/inventory ansible/playbooks/... --limit wireless_ap \
  -e openwrt_discovery_pubkey="ssh-ed25519 AAAA… openwrt-discovery" --check --diff
```

(Run `--check --diff` first — highest-blast-radius discipline. The role adds one `authorized_keys` line; a second
run reports `0 changed`.)

## Entrypoints

| `tasks_from:` | Does |
|---|---|
| `main` (default) | Authorize the read-only forced-command key (idempotent `lineinfile`, `--check`-safe, `no_log`). |
| `backup` | Capture the prior `authorized_keys` as the rollback reference (read-only slurp → control-side). |

## Knobs

| var | default | meaning |
|---|---|---|
| `openwrt_discovery_pubkey` | `""` | the sweep's read-only **public** key (empty → no-op) |

The forced command (`cat /tmp/dhcp.leases`) + `no-pty,no-*-forwarding` mean the key can run **only** that one read —
never a shell, never another file. See also: [`discovery/README.md`](../../../discovery/README.md),
[SECURITY.md C18](../../../SECURITY.md) (accepted-risk **R-DISC-2**),
[`roles/logging_file_tail_ssh`](../logging_file_tail_ssh/README.md) — the sibling forced-command read-key role.
