"""_diff — the field-level reconfigure DIFFER (Phase 4a, #138).

These pin service/_diff.compute_changes + severity_decision. WHY (the failure they guard): the diff is what the
operator reviews before a reconfigure stages, and the `severity`/`will_overwrite` it computes drive the
overwrite-confirm + the token's no-quiet-upgrade fold. If a value CLOBBER were mislabelled `add` (instead of
`modify`), the UI would skip the confirm and silently overwrite a current value — the exact danger goal-2 turns
from rare into routine. So every kind is pinned with its before/after, and severity is asserted to be the max.
"""
import pytest

from kontroll.service._diff import compute_changes, effective_severity, severity_decision

pytestmark = pytest.mark.unit


def test_no_change_is_an_empty_diff_with_no_severity():
    """current == proposed → no changes, severity None, empty will_overwrite — the idempotent no-op the dialog
    renders as 'no changes'. Guards a same-value re-submit being treated as a clobber."""
    cur = {"snmp": {"module": "if_mib"}}
    d = compute_changes(cur, dict(cur))
    assert d["changes"] == [] and d["severity"] is None and d["will_overwrite"] == []


def test_new_method_is_add_co_owner_safe():
    """A method absent in current → a single `add` change, severity `add`, empty will_overwrite (co-owner-safe,
    no confirm). Guards the add path staying confirm-free (backward-compatible with first-write)."""
    d = compute_changes({}, {"host_node": {}})
    assert d["changes"] == [{"path": "host_node", "kind": "add", "after": {}}]
    assert d["severity"] == "add" and d["will_overwrite"] == []


def test_changed_param_is_modify_and_in_will_overwrite():
    """An existing method's param whose value differs → a `modify` change carrying before/after, severity
    `modify`, and the param path in will_overwrite (the clobber set the confirm enumerates). THE load-bearing
    case: a value replace must NOT be labelled `add`."""
    d = compute_changes({"snmp": {"module": "if_mib"}}, {"snmp": {"module": "system"}})
    assert d["changes"] == [{"path": "snmp.module", "kind": "modify", "before": "if_mib", "after": "system"}]
    assert d["severity"] == "modify" and d["will_overwrite"] == ["snmp.module"]


def test_dropped_method_and_param_are_remove():
    """A method present in current but absent in proposed → `remove` of the entry; a param dropped from an
    existing method → `remove` of that param. Guards the no-drop set the confirm + verify_no_drop key off."""
    d_entry = compute_changes({"icmp": {}, "snmp": {"module": "if_mib"}}, {"snmp": {"module": "if_mib"}})
    assert {"path": "icmp", "kind": "remove", "before": {}} in d_entry["changes"]
    d_param = compute_changes({"snmp": {"module": "if_mib", "auth": "v3"}}, {"snmp": {"module": "if_mib"}})
    assert {"path": "snmp.auth", "kind": "remove", "before": "v3"} in d_param["changes"]


def test_severity_is_the_max_over_the_change_set():
    """severity is the max kind across all changes (add < modify < remove) — so a change-set with any remove is
    `remove`, with a modify (no remove) is `modify`. Guards the confirm weight being downgraded by a benign add
    in the same set."""
    d = compute_changes({"a": {"p": "1"}}, {"a": {"p": "2"}, "b": {}})   # one modify + one add
    assert d["severity"] == "modify"
    d2 = compute_changes({"a": {"p": "1"}, "z": {}}, {"a": {"p": "2"}})   # one modify + one remove
    assert d2["severity"] == "remove"


def test_flat_scalar_shape_diffs_per_key():
    """A FLAT `{key: scalar}` struct (module identity / platform settings — Phase 4b) diffs per key: an unchanged
    key is no change, a changed key is a `modify` carrying before/after at the key path (not `key.param`), a new
    key is an `add`, a dropped key a `remove`. Guards the scalar branch that lets identity/settings ride the SAME
    differ as the nested capability params — a flat surface must not need its own bespoke differ."""
    d = compute_changes({"secrets_domain": "network", "status": "active"},
                        {"secrets_domain": "semaphore", "status": "active"})
    assert d["changes"] == [{"path": "secrets_domain", "kind": "modify",
                             "before": "network", "after": "semaphore"}]
    assert d["will_overwrite"] == ["secrets_domain"] and d["severity"] == "modify"
    assert compute_changes({"a": "1"}, {"a": "1", "b": "2"})["changes"] == [
        {"path": "b", "kind": "add", "after": "2"}]                       # a new flat key → add
    assert compute_changes({"a": "1", "z": "9"}, {"a": "1"})["changes"] == [
        {"path": "z", "kind": "remove", "before": "9"}]                   # a dropped flat key → remove


def test_a_none_valued_flat_key_is_distinguished_from_absent():
    """A flat key whose CURRENT value is None (a settings knob that isn't set) is distinguished from an ABSENT
    key by the _MISSING sentinel: setting it None→"x" is a `modify`, not skipped. Guards the `current.get(k)`
    is-None ambiguity (an unset knob looking identical to a missing one would drop the change)."""
    d = compute_changes({"tls_mode": None}, {"tls_mode": "self_signed"})
    assert d["changes"] == [{"path": "tls_mode", "kind": "modify", "before": None, "after": "self_signed"}]


def test_knob_meta_upgrades_a_modify_to_identity_but_never_an_add():
    """`knob_meta` UPGRADES a MODIFY of a declared `identity` knob to `severity: identity` (+ stamps blast_radius)
    so the gate fires the type-to-confirm; an ADD (first-set) of the SAME knob stays `add` (co-owner-safe, design
    22 §10). Guards the two failures: (a) an identity re-point rendered as a plain modify-confirm (under-gated),
    and (b) a first-set over-gated as identity. effective_severity is what the diff `severity` + the gate read."""
    meta = {"secrets_domain": {"severity": "identity", "blast_radius": "orphan-creds"}}
    up = compute_changes({"secrets_domain": "network"}, {"secrets_domain": "semaphore"}, meta)
    assert up["changes"][0]["severity"] == "identity" and up["changes"][0]["blast_radius"] == "orphan-creds"
    assert up["severity"] == "identity"
    add = compute_changes({}, {"secrets_domain": "network"}, meta)        # first-set — NOT upgraded
    assert add["changes"][0]["kind"] == "add" and "severity" not in add["changes"][0]
    assert add["severity"] == "add"
    # severity_decision folds the UPGRADED severity so the token locks the identity decision (no-quiet-upgrade, M1)
    assert severity_decision(up) == "identity|secrets_domain"


def test_knob_meta_never_downgrades_and_is_absent_for_unlisted_knobs():
    """A knob_meta `severity` LOWER than the kind never downgrades (max-only), and a knob with no metadata keeps
    its kind. Guards a descriptor typo silently weakening a remove, and a non-identity knob being mislabelled."""
    weak = {"x": {"severity": "modify"}}                                  # modify is not > a remove
    d = compute_changes({"x": "1"}, {})
    d2 = compute_changes({"x": "1"}, {}, weak)
    assert effective_severity(d["changes"][0]) == "remove" == effective_severity(d2["changes"][0])
    assert compute_changes({"y": "1"}, {"y": "2"}, weak)["severity"] == "modify"   # unlisted → kind


def test_severity_decision_is_canonical_and_order_stable():
    """severity_decision folds {severity, sorted(will_overwrite)} into one stable string the token locks — a
    MORE-destructive recomputed plan yields a DIFFERENT string (no-quiet-upgrade, M1). Guards that reordering
    will_overwrite can't change the token, and that add vs modify produce different decisions."""
    a = compute_changes({"m": {"x": "1", "y": "2"}}, {"m": {"x": "9", "y": "8"}})
    assert severity_decision(a) == "modify|m.x,m.y"                       # sorted, stable
    assert severity_decision(compute_changes({}, {"m": {}})) == "add|"    # an add is a distinct decision
    assert severity_decision(compute_changes({"m": {}}, {"m": {}})) == "none|"   # a no-op is the 'none' sentinel
