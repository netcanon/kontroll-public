"""Hermetic shape pins for the hand-authored logs dashboard (Layer 3, no live Grafana in CI).

Guards two silent-failure classes a logs dashboard can ship with: (1) a panel/target/template-var that pins the
WRONG (or no) datasource uid → a live 'No data' / 'datasource not found' that only shows post-deploy; (2) a
panel that splits/series-by a label Loki does NOT index (i.e. outside the canonical C12 set) → implies Loki
indexes a high-cardinality/secret-adjacent label, a C12 drift. Also pins the run_id template var is scoped to
source="internal" (the capability sink carries no run_id by design — an unscoped var would render empty).
"""
import json
import os
import re

import pytest

pytestmark = pytest.mark.unit

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DASH = os.path.join(_ROOT, "dashboards", "grafana", "dashboards", "logs.json")

# the canonical, non-secret label set Loki indexes (C12) — a panel may only split/select by these.
_CANONICAL_LABELS = {"source", "host", "service", "level", "run_id", "device"}
# the closed set of template variable names this dashboard is allowed to define (no free-text label vars).
_ALLOWED_VARS = {"source", "service", "level", "run_id", "search"}


def _dash():
    with open(_DASH, encoding="utf-8") as fh:
        return json.load(fh)


def test_logs_dashboard_parses_and_has_uid():
    """logs.json is valid JSON with a stable top-level uid (provisioned dashboards need a fixed uid)."""
    d = _dash()
    assert d.get("uid"), "logs.json must declare a stable top-level uid"
    assert d.get("panels"), "logs.json must have panels"


def test_every_panel_and_target_pins_the_loki_datasource_uid():
    """Every panel AND every target pins {type:loki, uid:loki} — a wrong/missing uid is a silent post-deploy
    'No data'. The uid is the fixed contract from provisioning/datasources/loki.yml (never renamed live)."""
    for p in _dash()["panels"]:
        assert p.get("datasource", {}).get("uid") == "loki", "panel %r datasource uid != loki" % p.get("title")
        for t in p.get("targets", []):
            assert t.get("datasource", {}).get("uid") == "loki", \
                "a target in panel %r does not pin datasource uid loki" % p.get("title")


def test_template_vars_are_the_closed_allowed_set_and_query_vars_pin_loki():
    """Template var names are the closed allowed set (no surprise free-text label var), and every QUERY-type
    var pins the loki datasource. level is a custom (closed) set, search is a textbox — neither is a label."""
    for v in _dash()["templating"]["list"]:
        assert v["name"] in _ALLOWED_VARS, "unexpected template var %r (not in the closed allowed set)" % v["name"]
        if v.get("type") == "query":
            assert v.get("datasource", {}).get("uid") == "loki", "query var %r must pin loki" % v["name"]


def test_run_id_var_is_scoped_to_internal_source():
    """The run_id template var is scoped to {source="internal"} — the capability sink carries no run_id (device
    logs are not part of a kontroll run), so an unscoped run_id var would render mostly-empty (R3 A6)."""
    v = next(x for x in _dash()["templating"]["list"] if x["name"] == "run_id")
    assert 'source="internal"' in v.get("query", ""), "run_id var must be scoped to source=\"internal\""


def test_no_panel_splits_by_a_noncanonical_label():
    """No panel aggregates `by (<label>)` on a label outside the canonical C12 set — a non-canonical split would
    imply Loki indexes a high-cardinality/secret-adjacent label (C12 drift). Body search stays a |~ filter."""
    text = json.dumps(_dash())
    for label in re.findall(r"by \(([^)]*)\)", text):
        for one in re.split(r"[,\s]+", label.strip()):
            if one:
                assert one in _CANONICAL_LABELS, "panel splits by non-canonical label %r (C12 drift)" % one
