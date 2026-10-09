"""classify.applicable_methods — the Stage-1 telemetry picker offerability filter (`applies_when`).

Pins the per-method `applies_when` filter built for Phase 7 (docs/observability/secondary-capability-dialog.md
§3.4): a CLI/NETCONF network device is offered snmp; the Proxmox collection is offered pve; the universal
methods (host_node/blackbox, no applies_when) are offered to everything; a hypervisor or a pure-REST/no-signal
device is NOT auto-offered snmp/pve. Guards BOTH over-offering (snmp for a hypervisor, pve for a switch) and
under-offering (a network device missing snmp), and that the filter reuses the existing three-valued predicate
engine rather than inventing new grammar. Offerability is permissive and is not a gate — the picker later
unions it with what's already declared.
"""
import pytest

from kontroll import catalog
from kontroll.service.classify import applicable_methods

pytestmark = pytest.mark.unit


def _names(facts):
    return {m["name"] for m in applicable_methods(facts, methods=catalog.load_telemetry())}


def test_universal_methods_offered_to_everything(make_facts):
    """host_node and blackbox (no applies_when) are offered for ANY device — even a no-signal one — because
    any box might run node_exporter and any address can be pinged. Guards a regression that hides the
    always-available host-agent / reachability options behind a predicate."""
    assert {"host_node", "blackbox"} <= _names(make_facts(modules=["thing"], plugins={}))


def test_network_cli_device_is_offered_snmp(make_facts):
    """A cliconf (network_cli) device — the Cisco switch's shape — is offered snmp. Guards under-offering:
    the agent-less method that actually fits managed network gear must surface in the picker."""
    assert "snmp" in _names(make_facts(plugins={"cliconf": ["ios"]}, modules=["ios_command"]))


def test_proxmox_collection_is_offered_pve_a_switch_is_not(make_facts):
    """The Proxmox collection (a proxmox_* module present) is offered pve; a cliconf network device is NOT
    (pve is the Proxmox-specific API exporter). Guards over-offering pve to non-Proxmox classes."""
    assert "pve" in _names(make_facts(modules=["proxmox_kvm", "proxmox_vm_info"]))
    assert "pve" not in _names(make_facts(plugins={"cliconf": ["ios"]}, modules=["ios_command"]))


def test_hypervisor_is_not_offered_snmp(make_facts):
    """A Proxmox host (no cliconf/netconf) is NOT offered snmp — you monitor a PVE host via host_node + pve,
    not SNMP. Guards over-offering snmp to a device class that has no SNMP story."""
    assert "snmp" not in _names(make_facts(modules=["proxmox_kvm"], plugins={}))


def test_pure_rest_service_is_not_auto_offered_snmp(make_facts):
    """An httpapi-only service (a REST app, no cliconf/netconf) is NOT auto-offered snmp — snmp's applies_when
    is precise to CLI/NETCONF network gear, so the picker stays honest for the radarr/exportarr service case.
    (An httpapi FortiGate still gets snmp in the real picker, but via the DECLARED union, not applies_when —
    offerability is not a gate.)"""
    assert "snmp" not in _names(make_facts(plugins={"httpapi": ["radarr"]}, modules=["x"]))
