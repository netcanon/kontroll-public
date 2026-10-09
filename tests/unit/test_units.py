"""Runnable-unit enumeration (R1 of the GUI-actuation build): the prober + the service resolver + the SEC-3
traversal guard.

WHY (the failures these guard):
  * `units_in_collection` must surface a collection's collection-shipped playbooks and roles (the launchable
    units) — and ONLY those (a module is a task, not runnable), reading files only, so the app-store can project
    a search result into pickable units. A collection that ships only modules (kontroll's device fleet — see the
    worked extraction) must yield empty, not error.
  * `service_units` must resolve the requested collection against the ENUMERATED installed set and walk only its
    on-disk base_path — the SEC-3 guard. The failure this prevents: a route param like `../../etc` or any crafted
    name being `os.path.join`'d and reading outside the installed collections' dirs. An absent/crafted name must
    return None (→ 404) WITHOUT ever walking the filesystem.
  * `service_units` is a READ view; it must never gain an actuation path (the read-only-by-construction contract).
"""
import os

import pytest

from _readonly_pins import assert_read_only
from kontroll import probe
from kontroll.service.units import service_units, validate_unit_config

pytestmark = pytest.mark.unit


@pytest.fixture
def tmp_collection(tmp_path):
    """A throwaway `ansible_collections` tree holding ONE collection `ns.demo` that ships 2 playbooks, 2 roles,
    and noise (a README, a non-dir file under roles/, a non-yaml file under playbooks/) the prober must ignore.
    Returns (base_path, 'ns.demo')."""
    cdir = tmp_path / "ns" / "demo"
    (cdir / "playbooks").mkdir(parents=True)
    (cdir / "roles" / "configure").mkdir(parents=True)
    (cdir / "roles" / "deploy").mkdir(parents=True)
    (cdir / "playbooks" / "site.yml").write_text("---\n", encoding="utf-8")
    (cdir / "playbooks" / "backup.yaml").write_text("---\n", encoding="utf-8")
    (cdir / "playbooks" / "README.md").write_text("not a playbook\n", encoding="utf-8")
    (cdir / "roles" / "NOTES.txt").write_text("not a role dir\n", encoding="utf-8")
    return str(tmp_path), "ns.demo"


def test_units_in_collection_finds_playbooks_and_roles(tmp_collection):
    """The prober lists collection-shipped playbooks (base name, .yml AND .yaml) + role dirs, sorted, and ignores
    the README / non-dir / non-yaml noise — the files-only shallow grain GET /units rides."""
    base, coll = tmp_collection
    units = probe.units_in_collection(coll, base)
    assert units["collection_playbook"] == ["backup", "site"]    # sorted; .yaml + .yml; README.md excluded
    assert units["role"] == ["configure", "deploy"]              # sorted role DIRS; NOTES.txt excluded


def test_units_in_collection_empty_for_modules_only(tmp_path):
    """A collection with neither playbooks/ nor roles/ (the device-management fleet ships only modules) yields
    empty lists, not an error — the honest result the worked extraction predicts."""
    (tmp_path / "ns" / "mods" / "plugins" / "modules").mkdir(parents=True)
    units = probe.units_in_collection("ns.mods", str(tmp_path))
    assert units == {"collection_playbook": [], "role": []}


def test_service_units_projects_units_with_stable_ids(tmp_collection):
    """service_units resolves the collection against the injected installed set and returns units ordered by the
    closed kind set (playbooks before roles), each with a `<collection>/<kind>/<name>` id."""
    base, coll = tmp_collection
    installed = {base: {coll: {"version": "1.0.0"}}}
    out = service_units(coll, installed=installed)
    assert out["collection"] == coll
    ids = [u["id"] for u in out["units"]]
    assert ids == ["ns.demo/collection_playbook/backup", "ns.demo/collection_playbook/site",
                   "ns.demo/role/configure", "ns.demo/role/deploy"]
    assert {u["kind"] for u in out["units"]} == {"collection_playbook", "role"}


def test_service_units_not_installed_returns_none(tmp_collection):
    """A collection absent from the installed set returns None (the route maps to 404) — never a 500/empty record."""
    base, coll = tmp_collection
    installed = {base: {coll: {"version": "1.0.0"}}}
    assert service_units("ns.absent", installed=installed) is None


def test_service_units_traversal_guard_never_walks_on_miss(tmp_collection, monkeypatch):
    """SEC-3: a crafted/absent `collection` must be rejected by the installed-set membership check BEFORE any
    filesystem walk — so it can never read outside the installed collections' dirs. Proven by making the walker
    EXPLODE if reached: for a non-member name, service_units must still return None without calling it."""
    base, coll = tmp_collection
    installed = {base: {coll: {"version": "1.0.0"}}}

    def boom(*a, **k):
        raise AssertionError("units_in_collection walked the filesystem for an unresolved collection param")
    monkeypatch.setattr(probe, "units_in_collection", boom)

    for crafted in ("../../../etc", "ns.demo/../../etc", "..", "ns.absent", "", "/etc/passwd"):
        assert service_units(crafted, installed=installed) is None   # rejected pre-walk; boom never raised


def test_service_units_is_read_only():
    """service_units is a READ view (the C10 read-only-by-construction contract): the AST pin asserts it calls no
    write/actuation verb and opens no file for writing."""
    assert_read_only("scripts/kontroll/service/units.py", "service_units")


def test_registered_units_view_is_read_only():
    """registered_units_view (the Automations-index projection) + its _has_values existence check are READ views —
    they project the registry + check whether a vars.yml exists, but stage nothing. The AST pin asserts neither
    calls a write/actuation verb nor opens a file for writing, so the Automations READ surface can never silently
    gain a write path (the configure write is the separate, WRITE_VERBS-registered stage_plan/apply_actuation_plan)."""
    assert_read_only("scripts/kontroll/service/units.py", "registered_units_view")
    assert_read_only("scripts/kontroll/service/units.py", "_has_values")


# ── validate_unit_config (the R3 configure-form server gate) ────────────────────────────────────────────────────
UNIT = {"key": "backup-ios", "knobs": [
    {"key": "mode", "type": "enum", "allowed": ["fast", "safe"], "required": True},
    {"key": "retries", "type": "int", "range": {"min": 0, "max": 5}},
    {"key": "enabled", "type": "bool"}]}


def test_validate_unit_config_accepts_valid_values():
    """Well-typed values for every knob validate clean (ok=True, no errors) — the configure stage may advance.
    A bool False and an int 0 are PRESENT values (not 'missing'), so they validate, not skip."""
    out = validate_unit_config("backup-ios", {"mode": "safe", "retries": 0, "enabled": False}, unit=UNIT)
    assert out == {"error": None, "ok": True, "errors": {}}


def test_validate_unit_config_rejects_unknown_knob():
    """A submitted key the descriptor doesn't declare is rejected (the CLOSED allow-list) — no un-described var
    can ride to a later stage. This is the config-injection guard at the unit boundary."""
    out = validate_unit_config("backup-ios", {"mode": "safe", "rogue": "x"}, unit=UNIT)
    assert out["ok"] is False and "rogue" in out["errors"]


def test_validate_unit_config_required_missing_is_an_error():
    """A required knob with no submitted value is an error; a non-required knob simply omitted is fine (the
    server treats absence as 'unchanged/default')."""
    out = validate_unit_config("backup-ios", {"retries": 2}, unit=UNIT)   # 'mode' (required) omitted
    assert out["ok"] is False and "mode" in out["errors"] and "retries" not in out["errors"]


def test_validate_unit_config_rejects_out_of_range_value():
    """A present value that fails its knob's validator (an int above range.max) is rejected via the SAME P0a
    _validate guard the rest of the GUI uses — the widget is convenience, this is the contract."""
    out = validate_unit_config("backup-ios", {"mode": "fast", "retries": 99}, unit=UNIT)
    assert out["ok"] is False and "retries" in out["errors"]


def test_validate_unit_config_no_unit():
    """An absent actuation unit returns {error:'no_unit'} (the route maps it to 404) — never a 500/empty pass.
    `unit=False` injects an explicit miss, so the assertion is deterministic (no real registry read)."""
    assert validate_unit_config("ghost", {"mode": "safe"}, unit=False) == {"error": "no_unit"}


def test_validate_unit_config_is_read_only():
    """validate_unit_config is a READ view (re-checks values, stages nothing): the AST pin asserts it calls no
    write/actuation verb and opens no file for writing — the read-only-by-construction contract for the gate."""
    assert_read_only("scripts/kontroll/service/units.py", "validate_unit_config")
