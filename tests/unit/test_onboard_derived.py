"""F2 onboard wiring: a BLIND onboard of a fresh collection now writes the AUTO-DERIVED metrics:/logs: floor into
the new module (so gen-observability/gen-logging generate its scrape targets + Vector drop-in with zero further
operator action — the empty-Grafana/empty-Loki defect closed) and carries the HONEST capability_gap in the plan.

WHY (the failure these guard): pre-F2, a blind onboard produced a module with EMPTY capability blocks by design —
a managed-but-unmonitored device. These pin that a cliconf onboard now ships a derived floor, that the floor is
marked `derived: true` (so gen-class-capabilities owns it), and — the load-bearing one — that a derivation bug
DEGRADES to no floor + a logged warning, NEVER a failed onboard (INVARIANT D*: a secondary capability can never
gate onboarding). The derivation reads the REAL registries (no paths.ROOT repoint here), so it exercises the
shipped confer maps + derive_defaults end-to-end through the planner.
"""
import pytest

from kontroll import catalog, probe
from kontroll.service import onboard

pytestmark = pytest.mark.unit


def _blind_plan(monkeypatch, plugins, modules, collection="arista.eos", key="arista_eos_auto", **kw):
    """A real onboard plan for a FRESH collection/key (no existing module ⇒ the non-reuse derive path), with a
    canned deep-probe. No paths.ROOT repoint ⇒ derive_class_capabilities reads the SHIPPED telemetry/logging/backend
    registries (the point: prove the wiring against the real confer maps)."""
    monkeypatch.setattr(catalog, "local_installed", lambda: {collection: "1.0.0"})

    def _fake(coll, version=None):
        f = probe._facts(coll, "1.0.0", "local", "deep")
        f["plugins"] = plugins
        f["modules"] = modules
        return f
    monkeypatch.setattr(probe, "deep_probe", _fake)
    return onboard.build_onboard_plan(collection, key, "core_switch", "192.0.2.30",
                                      host_name="sw9", secrets="network", **kw)


def test_blind_cliconf_onboard_emits_the_derived_metrics_and_logs_floor(monkeypatch):
    """A blind network_cli onboard writes metrics [snmp(if_mib), blackbox(icmp)] + logs [syslog_push(tcp)] into the
    NEW module, each marked `derived: true`, plus the class-level `derived: true` flag — so the device is monitored
    + log-shippable on day one with zero curation. Guards the empty-Grafana/empty-Loki defect re-appearing."""
    plan = _blind_plan(monkeypatch, {"cliconf": ["eos"]}, ["eos_command"])
    mod = plan["module"]
    assert mod.get("derived") is True
    assert [m["method"] for m in mod["metrics"]] == ["snmp", "blackbox"]
    assert all(m.get("derived") for m in mod["metrics"])
    assert mod["metrics"][0]["params"] == {"module": "if_mib"}
    assert [m["method"] for m in mod["logs"]] == ["syslog_push"]
    assert mod["logs"][0]["params"] == {"transport": "tcp"} and mod["logs"][0].get("derived") is True
    assert plan["capability_gap"] == []                       # cisco-class cliconf gear is full-parity


def test_blind_proxmox_shaped_onboard_surfaces_the_pve_gap_non_gating(monkeypatch):
    """A proxmox-shaped device (module proxmox_kvm → raw_ssh) derives the universal floor (blackbox + host_node) but
    the vendor `pve` exporter is NOT faked — it is named in the NON-GATING capability_gap (declare it to enable
    VM/LXC metrics). Guards both the honest gap surfacing and the never-fake invariant on the onboard path."""
    plan = _blind_plan(monkeypatch, {}, ["proxmox_kvm"], collection="community.proxmox", key="proxmox_auto")
    assert plan["error"] is None and plan["backend"] == "raw_ssh"
    assert {m["method"] for m in plan["module"]["metrics"]} == {"blackbox", "host_node"}
    assert any(g["method"] == "pve" for g in plan["capability_gap"])


def test_onboard_derivation_failure_degrades_to_no_floor_never_fails(monkeypatch):
    """INVARIANT D* (the load-bearing pin): a derivation EXCEPTION must NOT fail the onboard — the module ships with
    no derived floor + a logged warning, and the plan is otherwise complete. Guards a derivation bug ever gating
    onboarding (a secondary capability is strictly best-effort)."""
    def _boom(*a, **k):
        raise RuntimeError("derivation blew up")
    monkeypatch.setattr(onboard, "derive_class_capabilities", _boom)
    plan = _blind_plan(monkeypatch, {"cliconf": ["eos"]}, ["eos_command"])
    assert plan["error"] is None
    assert "metrics" not in plan["module"] and "logs" not in plan["module"]
    assert "derived" not in plan["module"] and plan["capability_gap"] == []
