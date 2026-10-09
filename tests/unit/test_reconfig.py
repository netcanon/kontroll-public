"""_reconfig — the no-drop INVARIANT + the reconfigure read-only pins (Phase 4a, #138).

These pin service/_reconfig.verify_no_drop (the MACHINE anti-clobber gate) and assert the reconfigure read/diff
seams are read-only-by-construction. WHY (the failure they guard): verify_no_drop is the structural defence
against a reconfigure silently DROPPING a co-owner's declared method/param — the cross-seam same-file race where
two dialogs each compute a `text_after` off a now-stale `text_before`. The token catches byte drift; this catches
a vanished co-owner. It MUST fail-closed (return False) on any unauthorized disappearance, or a clobber slips
past the promote. The read-only pins guard the current_values/compute_changes/verify_no_drop path ever gaining a
write — the read half of the reconfigure must never mutate.
"""
import pytest

from _readonly_pins import assert_read_only
from kontroll.service import promote
from kontroll.service._reconfig import paths, run_promote, verify_no_drop

pytestmark = pytest.mark.unit


def test_verify_no_drop_true_when_nothing_drops():
    """A pure modify (no entry/param disappears) passes — the common reconfigure case. Guards verify_no_drop
    blocking a legitimate value change."""
    before = {"snmp": {"module": "if_mib"}}
    after = {"snmp": {"module": "system"}}
    assert verify_no_drop(before, after, [{"path": "snmp.module", "kind": "modify"}]) is True


def test_verify_no_drop_true_when_only_authorized_removes_are_gone():
    """An entry/param the change-set explicitly marks `remove` MAY be gone in after — that's authorized. Guards
    verify_no_drop refusing an intended, reviewed removal."""
    before = {"snmp": {"module": "if_mib"}, "icmp": {}}
    after = {"snmp": {"module": "if_mib"}}
    assert verify_no_drop(before, after, [{"path": "icmp", "kind": "remove"}]) is True


def test_verify_no_drop_false_when_an_unauthorized_entry_vanishes():
    """A co-owner's method present in before but gone in after, with NO `remove` authorizing it → False
    (fail-closed). THE anti-clobber case: a stale-text race that would drop another dialog's method must be
    refused at promote (no write)."""
    before = {"snmp": {"module": "if_mib"}, "host_node": {}}
    after = {"snmp": {"module": "system"}}                    # host_node silently dropped, unauthorized
    assert verify_no_drop(before, after, [{"path": "snmp.module", "kind": "modify"}]) is False


def test_verify_no_drop_false_when_an_unauthorized_param_vanishes():
    """A param present in before but gone in after, unauthorized → False. Guards a partial clobber that drops a
    co-owner's param while changing another."""
    before = {"snmp": {"module": "if_mib", "auth": "v3"}}
    after = {"snmp": {"module": "system"}}                    # auth dropped, unauthorized
    assert verify_no_drop(before, after, [{"path": "snmp.module", "kind": "modify"}]) is False


def test_paths_flattens_entries_and_params():
    """paths() yields both entry and entry.param keys — the granularity the change-set's remove paths match, so
    authorization is path-for-path. Guards a mismatch between the differ's paths and the invariant's."""
    assert paths({"snmp": {"module": "if_mib"}}) == {"snmp", "snmp.module"}


def test_paths_treats_a_flat_scalar_value_as_a_leaf():
    """paths() on a FLAT `{key: scalar}` struct (identity/settings) yields just the keys — a scalar value is NOT
    descended into (the isinstance(dict) guard). Guards the char-by-char iteration bug that would make
    verify_no_drop compare bogus per-character paths (`status.a`, `status.c`, …) and PASS a real drop on a flat
    surface (review invariant F)."""
    assert paths({"secrets_domain": "network", "status": "active"}) == {"secrets_domain", "status"}


def test_run_promote_runs_token_then_no_drop_then_apply_and_refuses_before_writing():
    """run_promote (the shared single-object promote identity/host ride) runs token → no_drop → apply IN ORDER and
    returns BEFORE apply on a failure: a bad token → `drift`; a recomputed plan whose `proposed` drops an
    unauthorized co-owner key → `would_drop`. apply_plan must run in NEITHER refusal. Guards the gate wiring — the
    machine anti-clobber + the anti-drift token both sit in front of every reconfigure write (and SHOULD-FIX 1's
    full-struct input makes `would_drop` actually reachable)."""
    applied = []
    apply = lambda p: applied.append(p) or {"changed": True, "paths": []}   # noqa: E731 — a 1-line test stub
    # a plan that DROPS co-owner key 'b' (present in current, absent in proposed) with no authorizing remove
    plan = {"error": None, "current": {"a": "1", "b": "2"}, "proposed": {"a": "9"},
            "changes": [{"path": "a", "kind": "modify", "before": "1", "after": "9"}],
            "token_parts": ["AFTER", "modify|a"]}
    good = promote.plan_token("AFTER", "modify|a")
    assert run_promote(lambda: plan, apply, "stale")["error"] == "drift" and not applied   # bad token → no apply
    out = run_promote(lambda: plan, apply, good)
    assert out["error"] == "would_drop" and not applied        # token OK, but a co-owner drops → no apply
    # a clean plan (nothing drops) DOES apply
    clean = dict(plan, proposed={"a": "9", "b": "2"})
    assert run_promote(lambda: clean, apply, good)["changed"] is True and len(applied) == 1


def test_reconfigure_read_and_diff_seams_are_read_only():
    """compute_changes, verify_no_drop, and each instance's current_values are read-only-by-construction (the
    shared AST pin, #133): no write/actuation verb, no file opened for writing. Guards the reconfigure READ/diff
    half ever gaining a mutation path."""
    assert_read_only("scripts/kontroll/service/_diff.py", "compute_changes")
    assert_read_only("scripts/kontroll/service/_reconfig.py", "verify_no_drop")
    assert_read_only("scripts/kontroll/service/observe.py", "current_values")
    assert_read_only("scripts/kontroll/service/backup.py", "current_values")
    assert_read_only("scripts/kontroll/service/logsvc.py", "current_values")
    # Phase 4b (#139): the module-identity + host-var read-backs + their configurable projections are
    # read-only-by-construction (a re-classify / re-IP READ must never mutate).
    assert_read_only("scripts/kontroll/service/identity.py", "current_values")
    assert_read_only("scripts/kontroll/service/hostvars.py", "current_values")
    assert_read_only("scripts/kontroll/service/hostvars.py", "_find_host")   # the read helper _host_view calls (NIT 1)
    assert_read_only("scripts/kontroll/service/configurable.py", "_identity_view")
    assert_read_only("scripts/kontroll/service/configurable.py", "_host_view")


def test_reconfigure_surfaces_never_reference_promote_ref():
    """Neither the identity nor the host-var module references `gitio.promote_ref` — the GUI proposer must NEVER
    be the promoter (C10 two-key). Guards a write-to-`main` hole sneaking into a reconfigure surface (review
    invariant D), mirroring the C10 boundary the rest of the GUI write path holds."""
    import os
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for rel in ("scripts/kontroll/service/identity.py", "scripts/kontroll/service/hostvars.py"):
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            assert "promote_ref" not in fh.read(), "%s must not reference promote_ref (C10)" % rel
