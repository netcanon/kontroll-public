"""capability — the capability-NEUTRAL orchestration spine (suggest / propose / promote dispatch).

These pin the seam's central guarantee (docs/observability/secondary-capability-dialog.md §3): the spine
dispatches the lifecycle over a descriptor by IMPORT-BY-CONVENTION with no `if cap==…` branch — suggest/
declared resolve the detection pair, propose/promote resolve the instance's write half. They guard that
PROPOSE is pure (review never writes), that PROMOTE is gated by the anti-drift token (a stale token is
refused, never applied), that an unregistered capability degrades cleanly (no crash), and — the no-two-source
pin — that the descriptor's picker hint equals classify's default so they cannot drift.
"""
import pytest

from kontroll import catalog
from kontroll.service import capability, classify
from kontroll.service.promote import plan_token

pytestmark = pytest.mark.unit

CAPS = catalog.load_capabilities()


def test_suggest_dispatches_to_the_telemetry_suggester(vectors, make_facts):
    """capability.suggest('telemetry', facts) routes through the descriptor to suggest_telemetry and returns
    its cell + candidates — the import-by-convention read path. Guards the dispatch resolving the right
    function (a cliconf device yields snmp among the candidates)."""
    s = capability.suggest("telemetry", make_facts(plugins={"cliconf": ["ios"]}), vectors=vectors, caps=CAPS)
    assert s and s["cell"]["state"] in ("yes", "maybe")
    assert "snmp" in s["candidates"]


def test_descriptor_hint_matches_classify_default_no_drift():
    """The telemetry descriptor's suggester.hint equals classify._TELEMETRY_HINT — the canonical copy lives in
    the descriptor, the lower-level onboard-nudge caller keeps the default, and this pin makes a silent
    divergence between the two a test failure (the no-two-source rule)."""
    tel = capability.get_descriptor("telemetry", CAPS)
    assert tel["suggester"]["hint"] == classify._TELEMETRY_HINT


def test_declared_dispatches_to_the_declared_reconciler(tmp_repo):
    """capability.declared('telemetry', collection) routes to declared_metrics_methods. Guards the
    DECLARED-side dispatch (an enabled module declaring metrics for the collection is found)."""
    import yaml
    (tmp_repo / "modules" / "demo").mkdir(parents=True)
    (tmp_repo / "modules" / "demo" / "module.yml").write_text(yaml.safe_dump({
        "key": "demo", "collections": [{"name": "ns.demo"}], "metrics": [{"method": "host_node"}]}),
        encoding="utf-8")
    # declared_<cap>(collection, fleet) — fleet passed positionally through the spine.
    got = capability.declared("telemetry", "ns.demo", {"enabled_modules": ["demo"]}, caps=CAPS)
    assert got and got[0]["key"] == "demo"


def test_propose_is_pure_and_carries_a_token(tmp_repo):
    """capability.propose returns a PURE plan (token + paths + enact) and writes nothing — the dialog's review
    step. Guards the propose/promote boundary at the spine level."""
    p = tmp_repo / "modules" / "demo_host"
    p.mkdir(parents=True)
    (p / "module.yml").write_text("key: demo_host\ninventory_group: hypervisors\n", encoding="utf-8")
    before = (p / "module.yml").read_text(encoding="utf-8")
    plan = capability.propose("telemetry", "demo_host", {"method": "host_node"}, caps=CAPS)
    assert plan["error"] is None and plan["plan_token"]
    assert (p / "module.yml").read_text(encoding="utf-8") == before


def test_promote_applies_with_a_matching_token(tmp_repo):
    """capability.promote with the proposed token applies the write (the block lands) — the happy path
    through dispatch + token gate + apply. (Regen no-ops under tmp_repo, so only the module write is asserted.)"""
    p = tmp_repo / "modules" / "demo_host"
    p.mkdir(parents=True)
    (p / "module.yml").write_text("key: demo_host\ninventory_group: hypervisors\n", encoding="utf-8")
    plan = capability.propose("telemetry", "demo_host", {"method": "host_node"}, caps=CAPS)
    out = capability.promote("telemetry", "demo_host", {"method": "host_node"}, plan["plan_token"], caps=CAPS)
    assert out["error"] is None and out["changed"] is True
    assert "- {method: host_node}" in (p / "module.yml").read_text(encoding="utf-8")


def test_promote_refuses_a_stale_token(tmp_repo):
    """capability.promote with a token that does not match the (re-computed) plan returns error 'drift' and
    writes NOTHING — the anti-drift gate at the spine. Guards a promote landing a plan the operator never
    reviewed."""
    p = tmp_repo / "modules" / "demo_host"
    p.mkdir(parents=True)
    (p / "module.yml").write_text("key: demo_host\ninventory_group: hypervisors\n", encoding="utf-8")
    before = (p / "module.yml").read_text(encoding="utf-8")
    out = capability.promote("telemetry", "demo_host", {"method": "host_node"},
                             plan_token("a-different-plan"), caps=CAPS)
    assert out["error"] == "drift"
    assert (p / "module.yml").read_text(encoding="utf-8") == before


def test_unregistered_capability_degrades_cleanly(make_facts):
    """An unknown capability is no_capability / None / [] across the spine — never a crash. Guards the route's
    404 path and the empty-registry case (a typo'd ?cap= must not 500)."""
    assert capability.suggest("nope", make_facts(), caps=CAPS) is None
    assert capability.declared("nope", "ns.x", caps=CAPS) == []
    assert capability.propose("nope", "k", {}, caps=CAPS)["error"] == "no_capability"
    assert capability.promote("nope", "k", {}, "tok", caps=CAPS)["error"] == "no_capability"
