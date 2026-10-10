# inventory — functional groups, drop-in hosts

A **directory inventory** (`ansible.cfg`: `inventory = ../instance/inventory`): Ansible merges every `*.yml`
source file here; `group_vars/` and `host_vars/` are special var dirs, not inventory sources. This is the seam
that lets the fleet grow *additively* — a new managed device is a **new file**, never an edit to a hub file.
`kontroll-init --fresh` scaffolds this directory from `instance.example/inventory/`.

## Layout

| File | Role |
|---|---|
| `hosts.yml` | The functional-group skeleton (`edge_firewall`, `core_switch`, `hypervisors`, …). Hand-maintained; hosts may be declared here by hand. |
| `onboarded-<key>.yml` | One file per onboarded device class, **machine-written** by the onboard planner (`scripts/galaxy.py onboard` or the GUI). Declares the host(s) into their group with their connection/backend vars inline. |
| `group_vars/<group>.yml` | Per-group defaults that are **vendor-neutral**: SSH transport, the bootstrap key path, the capture directory. `all.yml` ships `config_backup_dir`. |

## A functional group must NOT pin a vendor

Functional groups describe a device's **role in the network**, not its make. CLAUDE.md's one-dispatch-seam rule is
that the per-host `device_role` is the *only* place a host maps to a vendor role/collection — so `ansible_network_os`,
a vendor connection plugin (`network_cli`, `httpapi`, `netconf`) and vendor-specific credential lookups must not
appear in a group's `group_vars`. The failure mode is quiet: onboard a device of vendor B into a group whose vars pin
vendor A and it inherits A's `network_os`. Per-host vars from the drop-in do win, so it is survivable, which is
exactly why it goes unnoticed — the group has become a second, invisible dispatch seam competing with `device_role`.
Enforced by [`tests/unit/test_group_vars_are_vendor_neutral.py`](../../tests/unit/test_group_vars_are_vendor_neutral.py)
over this scaffold and over an instance's committed overlay.

## How a drop-in host resolves

Every drop-in carries its own connection vars inline — the onboard planner emits them from the backend's
`connection:` block — and points at the relevant SOPS domain for credentials. It does not depend on the group
supplying a vendor. With a directory inventory `inventory_dir` is `instance/inventory`, so a `group_vars/*.yml`
lookup of `inventory_dir ~ '/../secrets/<domain>.sops.yml'` resolves unchanged.

## Adding a host

- **Onboarding:** `python3 scripts/galaxy.py onboard <collection> --key <key> --group <group> --host <ip> --apply`
  writes `onboarded-<key>.yml` (plus the module declaration and the fleet enable), or use the GUI. See
  [scripts/README.md](../../scripts/README.md).
- **By hand:** add the host under its functional group in `hosts.yml`.
