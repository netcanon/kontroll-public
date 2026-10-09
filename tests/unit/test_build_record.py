"""build_record(facts, vectors, overrides, backends) — facts -> the result schema.

Covers the record shape the GUI + search render, the suggested/candidate backend
wiring, and the overrides layer: an override patches a capability and (critically)
YAML's bool coercion of `yes`/`no` is normalized back to our state strings.
"""
import pytest

import galaxy

pytestmark = pytest.mark.unit


def test_record_schema_and_backend_suggestion(vectors, backends, make_facts):
    """A built record carries the full schema the GUI/search render: collection, suggested +
    candidate backends, certified meta, a 3-valued state per vector, and provenance=derived."""
    f = make_facts(collection="cisco.ios", plugins={"cliconf": ["ios"]},
                   modules=["ios_command"], certified=True)
    rec = galaxy.build_record(f, vectors, {}, backends)

    assert rec["collection"] == "cisco.ios"
    assert rec["suggested_backend"] == "netcommon_cli"
    assert "netcommon_cli" in rec["backend_candidates"]
    assert rec["meta"]["certified"] is True
    assert rec["provenance"] == "derived"
    # every vector is represented, each with a 3-valued state
    assert set(rec["capabilities"]) == {v["name"] for v in vectors}
    assert "telemetry" in rec["capabilities"]   # the 4th vector cell is emitted (vectors/telemetry.yml)
    for cap in rec["capabilities"].values():
        assert cap["state"] in ("yes", "no", "maybe")
    assert rec["capabilities"]["backup"]["state"] == "yes"   # cliconf confers backup


def test_no_backend_when_nothing_matches(vectors, make_facts):
    """With an empty backend set, suggested_backend is None (not a crash)."""
    rec = galaxy.build_record(make_facts(), vectors, {}, [])
    assert rec["suggested_backend"] is None
    assert rec["backend_candidates"] == []


def test_override_normalizes_yaml_bool_state(vectors, backends, make_facts):
    """overrides/*.yml written as `state: yes` parses to Python True; build_record
    must coerce it back to the 'yes' string and stamp provenance=override."""
    f = make_facts(collection="acme.box")
    overrides = {"acme.box": {"capabilities": {"backup": {"state": True, "confidence": "high"}},
                              "note": "API-backup device — see overrides/"}}
    rec = galaxy.build_record(f, vectors, overrides, backends)

    assert rec["capabilities"]["backup"]["state"] == "yes"
    assert rec["capabilities"]["backup"]["provenance"] == "override"
    assert rec["meta"]["note"] == "API-backup device — see overrides/"
    assert rec["provenance"] == "derived+override"


def test_override_false_becomes_no(vectors, backends, make_facts):
    """An override of `state: false` (YAML bool) wins over a derived `yes`, coerced to the 'no'
    string — the operator can correct a wrong-positive derivation."""
    f = make_facts(collection="acme.box", plugins={"cliconf": ["x"]})   # would derive backup=yes
    overrides = {"acme.box": {"capabilities": {"backup": {"state": False}}}}
    rec = galaxy.build_record(f, vectors, overrides, backends)
    assert rec["capabilities"]["backup"]["state"] == "no"               # override wins
