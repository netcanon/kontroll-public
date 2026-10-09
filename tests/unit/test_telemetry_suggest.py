"""suggest_telemetry + declared_metrics_methods — the DETECTED->suggestion bridge and the DECLARED
reconciliation (scripts/kontroll/service/classify.py). Guards that detection produces a NON-binding method
hint (never a write), that host_node is never auto-primary (no fact proves the host runs an agent), and
that the declared side reads BOTH the {method} registry schema and a legacy {job, via} block.
"""
import pytest
import yaml

from kontroll.service.classify import declared_metrics_methods, suggest_telemetry

pytestmark = pytest.mark.unit


def test_suggest_offers_candidates_for_httpapi(vectors, make_facts):
    """An httpapi collection's suggestion is non-empty and includes an API exporter — the onboarding hint a
    scrapable REST device gets. Guards detection producing no actionable suggestion for a clear signal."""
    s = suggest_telemetry(make_facts(plugins={"httpapi": ["fortios"]}), vectors)
    assert s["cell"]["state"] == "yes"
    assert any("api" in c for c in s["candidates"])


def test_suggest_never_makes_host_node_primary(vectors, make_facts):
    """host_node is only ever a trailing/manual candidate, never first — no collection fact proves the
    managed host runs a node_exporter agent. Guards the hard rule that host-agent telemetry is
    OPERATOR-DECLARED, not vector-detected (the design's central honesty constraint)."""
    s = suggest_telemetry(make_facts(plugins={"httpapi": ["x"]}), vectors)
    assert not s["candidates"] or s["candidates"][0] != "host_node"


def test_suggest_empty_candidates_and_honest_note_when_no(vectors, make_facts):
    """A no-signal device yields telemetry=no, an empty candidate list, and the honest note that host_node
    is the only option if it is a host — guards suggesting a method for something with nothing to scrape."""
    s = suggest_telemetry(make_facts(modules=["thing"], plugins={}), vectors)
    assert s["cell"]["state"] == "no" and s["candidates"] == []
    assert "host_node" in s["note"]


def test_declared_reads_method_and_legacy_schema(tmp_repo):
    """declared_metrics_methods finds an enabled module declaring a metrics block for the collection under
    BOTH the registry {method, params} and a legacy {job, via} schema — the DECLARED side the
    telemetry-method redesign must not break. Guards the detection/declared bridge going blind when a
    module.yml uses either schema."""
    (tmp_repo / "modules" / "demo").mkdir(parents=True)
    (tmp_repo / "modules" / "demo" / "module.yml").write_text(yaml.safe_dump({
        "key": "demo", "collections": [{"name": "ns.demo"}],
        "metrics": [{"method": "host_node"}, {"job": "proxmox", "via": "proxy"}],
    }), encoding="utf-8")
    got = declared_metrics_methods("ns.demo", fleet={"enabled_modules": ["demo"]})
    assert got and got[0]["key"] == "demo"
    assert set(got[0]["methods"]) == {"host_node", "proxmox"}   # method OR job, both read


def test_declared_empty_for_unmonitored_collection(tmp_repo):
    """A collection no enabled module declares metrics for returns [] — guards a false 'already monitored'
    claim (a module present but with no metrics: block must not register as declared)."""
    (tmp_repo / "modules" / "demo").mkdir(parents=True)
    (tmp_repo / "modules" / "demo" / "module.yml").write_text(yaml.safe_dump({
        "key": "demo", "collections": [{"name": "ns.demo"}]}), encoding="utf-8")
    assert declared_metrics_methods("ns.demo", fleet={"enabled_modules": ["demo"]}) == []
