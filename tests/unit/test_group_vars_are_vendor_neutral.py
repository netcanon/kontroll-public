"""A functional inventory group must never pin a vendor.

CLAUDE.md's one-dispatch-seam rule: functional groups (`edge_firewall`, `core_switch`, …) plus per-host
`device_role` are the ONLY place a host maps to its role/collection — "never scatter per-vendor branching
across playbooks", and a group's `group_vars` is exactly such a scatter point.

Two files broke it and the inventory README documented the breakage as intended behaviour ("a drop-in that
joins `core_switch` inherits that group's connection type, `network_os`, and credential lookup"):

    instance/inventory/group_vars/edge_firewall.yml   ansible_network_os: fortinet.fortios.fortios
                                                      ansible_connection: httpapi
                                                      fortios_api_token: "{{ _net_secrets.fortios_api_token }}"
    instance/inventory/group_vars/core_switch.yml     ansible_network_os: cisco.ios.ios
                                                      ansible_connection: network_cli
                                                      ansible_user/password from _net_secrets.cisco_*

Both were deleted 2026-07-28. They had become actively wrong: the 2026-07-27 edge migration replaced the
FortiGate with OPNsense and the Cisco C9300 with a MikroTik on RouterOS
— the functional groups survived, the hardware did not — and they resolved credential
keys the live `network.sops.yml` no longer contains.

The failure mode is what makes this worth a permanent test rather than a one-off cleanup: onboard a MikroTik
into `core_switch` and it inherits a Cisco `network_os` from its group. Per-host vars from the drop-in do
win, so it was survivable in practice, which is precisely why it went unnoticed — the group had quietly
become a second, invisible dispatch seam competing with `device_role`. A vendor swap should be a drop-in
file, not an archaeology exercise.

Scope note: `all.yml` is exempt from the group check only in the sense that it is not a functional group;
it is still checked for vendor keys.
"""
import os

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Every group_vars dir that ships in the repo: the committed instance overlay and the fresh-install scaffold.
_GV_DIRS = [
    os.path.join(_ROOT, "instance", "inventory", "group_vars"),
    os.path.join(_ROOT, "instance.example", "inventory", "group_vars"),
]

# Vars that BIND A VENDOR. `ansible_connection` is deliberately NOT here: `ssh` is vendor-neutral transport
# and is a legitimate group default. The vendor-specific connection plugins are listed separately below.
_VENDOR_KEYS = ("ansible_network_os", "ansible_httpapi_use_ssl", "ansible_httpapi_port",
                "ansible_httpapi_validate_certs")
_VENDOR_CONNECTIONS = ("network_cli", "httpapi", "netconf")


def _group_var_files():
    for d in _GV_DIRS:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith((".yml", ".yaml")):
                yield os.path.join(d, fn)


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def test_no_group_vars_file_pins_a_vendor_network_os():
    """The regression. `ansible_network_os` in a functional group's vars is the one-dispatch-seam violation
    in its purest form: it names a vendor collection for every host in a role-defined group."""
    offenders = []
    for path in _group_var_files():
        doc = _load(path)
        for key in _VENDOR_KEYS:
            if key in doc:
                offenders.append("%s defines %s: %r" % (os.path.relpath(path, _ROOT), key, doc[key]))
    assert not offenders, (
        "a functional group must not bind a vendor — put it in the host's drop-in, keyed on device_role:\n  "
        + "\n  ".join(offenders))


def test_no_group_vars_file_uses_a_vendor_connection_plugin():
    """`network_cli`/`httpapi`/`netconf` are vendor-plane transports; `ssh` is not. A group may default the
    latter (all the SSH classes legitimately do) but never the former."""
    offenders = []
    for path in _group_var_files():
        conn = str(_load(path).get("ansible_connection", ""))
        if conn in _VENDOR_CONNECTIONS:
            offenders.append("%s sets ansible_connection: %s" % (os.path.relpath(path, _ROOT), conn))
    assert not offenders, "vendor-plane connection plugins belong in the drop-in:\n  " + "\n  ".join(offenders)


def test_no_group_vars_file_resolves_a_vendor_named_credential():
    """The credential half, and the half that rots hardest. `fortios_api_token`, `cisco_username` etc. name a
    vendor in the KEY, so the group silently depends on a SOPS domain containing that exact key. When the
    hardware changed, the key names changed and these lookups became references to nothing — resolvable only
    as a runtime failure, and under `no_log` a censored one."""
    offenders = []
    for path in _group_var_files():
        for key, value in _load(path).items():
            blob = "%s %s" % (key, value)
            for vendor in ("fortios", "fortigate", "cisco", "opnsense", "routeros", "mikrotik"):
                if vendor in blob.lower():
                    offenders.append("%s: %s -> %r" % (os.path.relpath(path, _ROOT), key, value))
                    break
    assert not offenders, (
        "vendor-named credentials/vars in group_vars tie a functional group to one make:\n  "
        + "\n  ".join(offenders))


def test_the_two_deleted_files_stay_deleted():
    """Named explicitly so a well-meaning restore (or a merge from an older branch) is caught. These are not
    files to repair — the hardware they describe is decommissioned."""
    for gone in ("edge_firewall.yml", "core_switch.yml"):
        path = os.path.join(_ROOT, "instance", "inventory", "group_vars", gone)
        assert not os.path.exists(path), (
            "%s is back. It pinned a vendor to a functional group and described hardware retired in the "
            "2026-07-27 edge migration — re-onboard the current device instead of restoring this." % gone)


def test_the_readme_documents_the_rule_it_used_to_contradict():
    """The inventory README actively taught the wrong pattern, which is why two files followed it. The corrected
    text is part of the fix, not decoration — and it ships in the scaffold (`instance.example/inventory/`, copied
    into every fresh instance by `kontroll-init --fresh`), so every new instance reads the rule where it would
    otherwise have read the violation."""
    readme = open(os.path.join(_ROOT, "instance.example", "inventory", "README.md"), encoding="utf-8").read()
    assert "must NOT pin a vendor" in readme, "the rule must be stated where the wrong pattern was taught"
    assert "device_role" in readme, "and must point at the seam that owns the mapping"
