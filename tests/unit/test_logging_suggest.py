"""suggest_logging + declared_logs_methods + the _LOGGING_HINT drift-pin (classify.py) — the DETECTED->nudge
bridge and the DECLARED reconciliation for the logging capability. Guards that detection produces a NON-binding
hint (never a write), that only network gear gets an auto-suggested method (the dominant journald/file sources
are operator-DECLARED), and that the hint can't drift from its canonical descriptor copy.
"""
import pytest
import yaml

from kontroll.service import classify
from kontroll.service.classify import declared_logs_methods, suggest_logging
from kontroll import catalog

pytestmark = pytest.mark.unit


def test_suggest_offers_syslog_for_cliconf_network_gear(vectors, make_facts):
    """A cliconf (network_cli) device's logging suggestion includes syslog_push — the only method a network
    box's collection signal justifies auto-suggesting. Guards detection producing no actionable nudge for a
    clear cliconf signal (the weak-but-real hint, mirroring telemetry's snmp suggestion)."""
    s = suggest_logging(make_facts(plugins={"cliconf": ["ios"]}), vectors)
    assert "syslog_push" in s["candidates"]


def test_suggest_never_auto_suggests_a_declared_only_source(vectors, make_facts):
    """journald/file/docker are host/runtime facts no probe sees, so they are NEVER auto-suggested — only the
    cliconf/netconf syslog signal is. A no-network-signal collection yields an empty candidate list + the
    honest 'declared in logs:' note. Guards the FLAG-1 honesty constraint (dominant log sources are
    operator-DECLARED, never vector-detected)."""
    s = suggest_logging(make_facts(modules=["thing"], plugins={"httpapi": ["x"]}), vectors)
    assert "journald_remote" not in s["candidates"] and "file_tail_ssh" not in s["candidates"]
    assert s["candidates"] == [] and "declared" in s["note"]


def test_suggest_is_pure_and_returns_the_three_keys(vectors, make_facts):
    """suggest_logging returns {cell, candidates, note} and writes nothing — the read-only purity of the
    suggester half (it can never gate onboarding or mutate). Guards a suggester that writes or gates."""
    s = suggest_logging(make_facts(plugins={"cliconf": ["ios"]}), vectors)
    assert set(s) == {"cell", "candidates", "note"} and isinstance(s["candidates"], list)


def test_declared_logs_methods_reads_the_logs_block(tmp_repo):
    """declared_logs_methods finds an enabled module declaring a `logs:` LIST for the collection and returns
    its sorted method names — the DECLARED-side reconciliation. Guards it going blind to a logs: block
    (mirror of declared_metrics_methods; block_shape: list)."""
    (tmp_repo / "modules" / "demo").mkdir(parents=True)
    (tmp_repo / "modules" / "demo" / "module.yml").write_text(yaml.safe_dump({
        "key": "demo", "collections": [{"name": "ns.demo"}],
        "logs": [{"method": "journald_remote"}, {"method": "file_tail_ssh"}]}), encoding="utf-8")
    (tmp_repo / "config").mkdir(exist_ok=True)
    (tmp_repo / "config" / "fleet.yml").write_text(yaml.safe_dump({"enabled_modules": ["demo"]}), encoding="utf-8")
    out = declared_logs_methods("ns.demo")
    assert out == [{"key": "demo", "methods": ["file_tail_ssh", "journald_remote"]}]


def test_declared_empty_for_an_unlogged_collection(tmp_repo):
    """A collection no enabled module declares `logs:` for returns [] — guards a false 'already shipping logs'
    claim (a module present but with no logs: block must not register as declared)."""
    (tmp_repo / "modules" / "demo").mkdir(parents=True)
    (tmp_repo / "modules" / "demo" / "module.yml").write_text(yaml.safe_dump({
        "key": "demo", "collections": [{"name": "ns.demo"}]}), encoding="utf-8")
    (tmp_repo / "config").mkdir(exist_ok=True)
    (tmp_repo / "config" / "fleet.yml").write_text(yaml.safe_dump({"enabled_modules": ["demo"]}), encoding="utf-8")
    assert declared_logs_methods("ns.demo") == []


def test_logging_hint_equals_descriptor_hint_no_drift():
    """classify._LOGGING_HINT == capabilities/logging.yml suggester.hint — the canonical copy lives in the
    descriptor; this pin makes a silent divergence a test failure (the no-two-source rule; mirror of the
    telemetry hint-drift pin)."""
    d = next(c for c in catalog.load_capabilities() if c["name"] == "logging")
    assert classify._LOGGING_HINT == d["suggester"]["hint"]
