"""observe — the telemetry instance (#1) of the secondary-capability seam: the metrics/dashboards write.

These pin the telemetry-specific half of Phase 7 (docs/observability/secondary-capability-dialog.md §2.1,
master §6 acceptance): PROPOSE writes nothing; the module-block write PRESERVES a hand-written module.yml's
comments (never a safe_dump flatten); the config-injection guard rejects an out-of-allow-list param BEFORE it
is written; ADD is idempotent (an already-declared method is refused, not duplicated); the plan_token gates
the exact declared block being written; and the enact step is hand-off STRINGS only (the API runs no play).
The regen-against-the-real-tree step is self-protecting (a no-op under tmp_repo), so these never touch the
real repo.
"""
import os

import pytest

from kontroll import catalog
from kontroll.service import observe, promote

pytestmark = pytest.mark.unit

METHODS = catalog.load_telemetry()

# A hand-written module.yml WITH comments + an existing metrics block — the proxmox/cisco shape the write
# must never flatten.
_COMMENTED = """# Device-class module: a network switch (hand-written, with comments).
key: demo_sw
description: demo switch
status: active
collections:
  - name: cisco.ios
role: backend_network_cli
inventory_group: core_switch   # a comment that must survive the write
metrics:
  - {method: snmp, params: {module: if_mib}}   # interface counters
"""


def _write_module(tmp_repo, key, text):
    d = tmp_repo / "modules" / key
    d.mkdir(parents=True)
    (d / "module.yml").write_text(text, encoding="utf-8")
    return d / "module.yml"


def test_propose_writes_nothing(tmp_repo):
    """build_telemetry_plan is PURE — after computing a plan, the module.yml on disk is byte-identical. Guards
    the propose/promote boundary: reviewing a plan must never mutate the repo (only promote writes)."""
    p = _write_module(tmp_repo, "demo_sw", _COMMENTED)
    before = p.read_text(encoding="utf-8")
    plan = observe.build_telemetry_plan("demo_sw", "host_node", methods=METHODS)
    assert plan["error"] is None
    assert p.read_text(encoding="utf-8") == before


def test_add_preserves_comments_and_existing_block(tmp_repo):
    """Adding host_node to a commented module appends to the metrics list and leaves every comment + the
    prior entry intact — the comment-preserving line-surgery, not a yaml round-trip. Guards the regression
    that flattens a hand-written module.yml (losing its access-chain/rationale comments)."""
    p = _write_module(tmp_repo, "demo_sw", _COMMENTED)
    plan = observe.build_telemetry_plan("demo_sw", "host_node", methods=METHODS)
    observe.apply_telemetry_plan(plan)
    after = p.read_text(encoding="utf-8")
    assert "# a comment that must survive the write" in after
    assert "- {method: snmp, params: {module: if_mib}}" in after   # the prior entry kept
    assert "- {method: host_node}" in after                        # the new entry added
    assert after.count("metrics:") == 1                            # appended INTO the block, not a 2nd block


def test_add_creates_block_when_absent(tmp_repo):
    """A class with NO metrics block gets a fresh `metrics:` block appended (the common case — onboard never
    writes a metrics block, INVARIANT D*). Guards the absent-block branch of the insert."""
    text = "key: demo_host\ndescription: a host\ninventory_group: hypervisors\n"
    p = _write_module(tmp_repo, "demo_host", text)
    plan = observe.build_telemetry_plan("demo_host", "host_node", methods=METHODS)
    observe.apply_telemetry_plan(plan)
    after = p.read_text(encoding="utf-8")
    assert "metrics:\n  - {method: host_node}" in after


def test_reconfigure_same_value_is_a_noop(tmp_repo):
    """Re-proposing a method the class already declares WITH THE SAME value is an idempotent no-op (Phase 4a
    replaced the `already_declared` wall with a reconfigure path): error None, an empty change-set, severity
    None, and text_after == text_before (writes nothing). Guards a same-value re-submit being treated as a
    clobber or duplicated as a second entry."""
    _write_module(tmp_repo, "demo_sw", _COMMENTED)
    plan = observe.build_telemetry_plan("demo_sw", "snmp", params={"module": "if_mib"}, methods=METHODS)
    assert plan["error"] is None and plan["changes"] == [] and plan["severity"] is None
    assert plan["text_after"] == plan["text_before"]   # the no-op writes nothing


def test_bad_param_is_rejected_before_write(tmp_repo):
    """A param value outside the method's allow-list (here a YAML-metacharacter injection) is `bad_param` —
    the config-injection guard, enforced in the propose path as defense-in-depth with the generator. Guards a
    crafted value ever reaching the rendered metrics entry."""
    _write_module(tmp_repo, "demo_sw2", _COMMENTED.replace("demo_sw", "demo_sw2").replace(
        "  - {method: snmp, params: {module: if_mib}}   # interface counters\n", ""))
    plan = observe.build_telemetry_plan("demo_sw2", "snmp",
                                        params={"module": "if_mib\ninjected: pwned"}, methods=METHODS)
    assert plan["error"] == "bad_param"


def test_unknown_method_and_not_onboarded(tmp_repo):
    """An unregistered method is `unknown_method`; a class with no module.yml is `not_onboarded`. Guards the
    dialog from proposing a write for a typo'd method or an un-onboarded class (the route turns each into the
    right 4xx)."""
    _write_module(tmp_repo, "demo_sw", _COMMENTED)
    assert observe.build_telemetry_plan("demo_sw", "nope", methods=METHODS)["error"] == "unknown_method"
    assert observe.build_telemetry_plan("ghost", "host_node", methods=METHODS)["error"] == "not_onboarded"


def test_plan_token_gates_the_written_block(tmp_repo):
    """The plan's token verifies against the text it will write, and FAILS for any other text — the
    propose→promote anti-drift gate applied to the telemetry write. Guards a promote landing a block the
    operator never reviewed."""
    _write_module(tmp_repo, "demo_host", "key: demo_host\ninventory_group: hypervisors\n")
    plan = observe.build_telemetry_plan("demo_host", "host_node", methods=METHODS)
    assert promote.verify_token(plan["plan_token"], *plan["token_parts"]) is True   # token_parts = [text_after, severity_decision]
    assert promote.verify_token(plan["plan_token"], plan["text_after"] + "drift", plan["token_parts"][1]) is False


def test_enact_commands_carry_kind_and_never_actuate(tmp_repo):
    """telemetry_enact_commands returns `{kind, why, cmd, …}` steps — the operator's hand-off, NEVER executed by
    the API (the PROPOSE/ENACT boundary). Each step declares its `kind`: 'semaphore' (a one-click Tier-1 task,
    naming a `task`) or 'operator' (a control-node command, Tier-2), and keeps a `cmd` CLI fallback + a `why`.
    The universal Prometheus reload is now a Semaphore task (HTTP reload), not a `docker exec kill -HUP` (item F)."""
    _write_module(tmp_repo, "demo_sw", _COMMENTED)
    plan = observe.build_telemetry_plan("demo_sw", "blackbox", params={"probe": "icmp"}, methods=METHODS)
    assert plan["error"] is None
    assert plan["enact"]
    for c in plan["enact"]:
        assert c["kind"] in ("semaphore", "operator")
        assert c["cmd"] and c["why"]                              # a CLI fallback + a rationale, always
        if c["kind"] == "semaphore":
            assert c["task"]                                      # a Semaphore task name to run
    reload = [c for c in plan["enact"] if c.get("task") == "reload-observability"]
    assert reload and reload[0]["kind"] == "semaphore"           # the reload is a Semaphore task, not a HUP
    assert not any("kill -HUP" in c["cmd"] for c in plan["enact"])


def test_grafana_links_deep_link_to_committed_uid(tmp_repo, monkeypatch):
    """The telemetry plan carries Grafana `links`: an 'Open Grafana' base + a `/d/<uid>` deep-link for each
    curated dashboard whose committed JSON pins a uid. WHY (#122): after observability onboarding the operator
    asked for a clickable jump to the device's Grafana page; the uid is read from the committed dashboard JSON so
    the deep-link is reproducible, the base comes from the deploy env, and links are EMPTY when no base is
    resolvable (never a fabricated host)."""
    _write_module(tmp_repo, "demo_host",
                  "key: demo_host\ninventory_group: hypervisors\ndashboards:\n  - {gnet: 1860, name: node}\n")
    dd = tmp_repo / "dashboards" / "grafana" / "dashboards"
    dd.mkdir(parents=True)
    (dd / "node.json").write_text('{"uid": "rYdddlPWk", "title": "Node Exporter Full"}', encoding="utf-8")
    # no mgmt base in env -> no links (never invent a host)
    monkeypatch.delenv("KONTROLL_MGMT_IP", raising=False)
    monkeypatch.delenv("KONTROLL_DOMAIN", raising=False)
    assert observe.build_telemetry_plan("demo_host", "host_node", methods=METHODS)["links"] == []
    # by-IP base -> an 'Open Grafana' link + the node dashboard /d/<uid> deep-link (HTTP :3002, like the Homepage tile)
    monkeypatch.setenv("KONTROLL_MGMT_IP", "203.0.113.9")
    urls = {l["url"] for l in observe.build_telemetry_plan("demo_host", "host_node", methods=METHODS)["links"]}
    assert "http://203.0.113.9:3002" in urls
    assert "http://203.0.113.9:3002/d/rYdddlPWk" in urls
    # by-domain fallback (no IP) -> the reverse-proxied grafana host
    monkeypatch.delenv("KONTROLL_MGMT_IP", raising=False)
    monkeypatch.setenv("KONTROLL_DOMAIN", "lab.example")
    base = observe.build_telemetry_plan("demo_host", "host_node", methods=METHODS)["links"][0]["url"]
    assert base == "https://grafana.lab.example"
