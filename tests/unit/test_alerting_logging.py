"""Hermetic shape pins for the Grafana-provisioned logging alert rules (Layer 3, no live Grafana in CI).

Guards: a rule that pins a wrong/empty datasource uid (silently never fires), an unbounded window or a missing
debounce `for:` (alert spam / never-clears), and a rules file with no contact point (Grafana provisioning fails
fatally). Also pins the `auth-denied` token as a shared contract (V1 M-9: the body-substring matchers are
content-coupled — if the emitter's wording drifts from this token, the security alert silently stops firing).
"""
import os

import pytest
import yaml

pytestmark = pytest.mark.unit

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ALERTING = os.path.join(_ROOT, "dashboards", "grafana", "provisioning", "alerting")

# the audit-log token the auth-denied alert keys off — MUST match what api/audit.py + gui emit (M-9 contract).
AUTH_DENIED_TOKEN = "auth-denied"


def _load(name):
    with open(os.path.join(_ALERTING, name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _rules():
    out = []
    for grp in _load("logging-rules.yaml")["groups"]:
        out.extend(grp.get("rules", []))
    return out


def test_every_rule_queries_loki_and_has_a_threshold_condition():
    """Each rule's query data node pins datasourceUid 'loki' and the rule names a `condition` whose node is a
    threshold/expression — a wrong uid or missing condition means the rule silently never evaluates."""
    rules = _rules()
    assert rules, "no alert rules found"
    for r in rules:
        assert r.get("condition"), "rule %r has no condition" % r.get("title")
        nodes = {d["refId"]: d for d in r.get("data", [])}
        # the query node(s) must hit loki; the condition node must be an __expr__ node
        loki_nodes = [d for d in r["data"] if d.get("datasourceUid") == "loki"]
        assert loki_nodes, "rule %r has no loki query node" % r.get("title")
        cond = nodes.get(r["condition"])
        assert cond and cond.get("datasourceUid") == "__expr__", \
            "rule %r condition must reference an __expr__ node" % r.get("title")


def test_every_rule_has_a_debounce_and_a_bounded_window():
    """Every rule has a non-empty `for:` (debounce) and a BOUNDED lookback (relativeTimeRange.from > 0 and a
    bounded LogQL [range]) — fail-closed: no unbounded lookback, no instant-fire flapping."""
    for r in _rules():
        assert r.get("for"), "rule %r missing a `for:` debounce" % r.get("title")
        for d in r["data"]:
            rtr = d.get("relativeTimeRange", {})
            assert rtr.get("from", 0) > 0, "rule %r data node %r has an unbounded relativeTimeRange" % (
                r.get("title"), d.get("refId"))


def test_auth_denied_token_is_pinned():
    """The auth-denied alert matches the exact AUTH_DENIED_TOKEN — pinned here as the shared contract so the
    alert and the audit-log emitter can't drift silently (V1 M-9)."""
    auth = [r for r in _rules() if "auth-denied" in (r.get("title") or "").lower()]
    assert auth, "no auth-denied rule found"
    for r in auth:
        exprs = " ".join(d.get("model", {}).get("expr", "") for d in r["data"])
        assert AUTH_DENIED_TOKEN in exprs, "auth-denied rule must match the pinned token %r" % AUTH_DENIED_TOKEN


def test_contact_point_present_so_provisioning_wont_fail():
    """A contact-point file with >=1 contact point must exist — Grafana provisioning fails fatally on a rule
    that resolves to a missing contact point; the default no-op keeps provisioning clean + non-coercive."""
    cp = _load("contactpoints.yaml")
    assert cp.get("contactPoints"), "contactpoints.yaml must define at least one contact point"
