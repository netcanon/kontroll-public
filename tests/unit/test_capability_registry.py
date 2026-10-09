"""The secondary-capability registry (capabilities/<cap>.yml) — catalog.load_capabilities() +
registered_capabilities().

These pin the foundation of the generalized secondary-capability dialog seam (Capability-track Phase 7,
docs/observability/secondary-capability-dialog.md §2). They guard that the registry is a true DROP-IN (a
dropped-in descriptor alone appears, with no loader edit — the modularity the whole seam rests on), that the
shipped telemetry descriptor carries every field the shell dispatches over (so the parameterized shell never
hits a missing key), and — critically — that the descriptor's wiring is REAL, not vapor: the suggester it
names must be an importable callable and the vector/generator it points at must exist on disk. The last pin
is what stops a descriptor from silently referencing a function or file that was renamed or never written.
"""
import importlib
import os

import pytest
import yaml

from kontroll import catalog, paths

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytestmark = pytest.mark.unit

# The fields the shared dialog/route/promote shell reads off EVERY descriptor (the parameterization
# contract). A descriptor missing one of these would make the generic shell raise at dispatch time.
_REQUIRED_TOP = {"name", "label", "order", "vector", "suggester", "service", "block_key", "block_shape",
                 "method_source", "render_method_stage", "resource_stage", "generator", "enact_kind"}
_REQUIRED_SUGGESTER = {"module", "suggest", "declared"}


def test_registry_loads_telemetry_sorted_by_order():
    """catalog.load_capabilities() discovers the capabilities/<cap>.yml drop-ins and returns them sorted by
    `order` — the registry the generalized seam consumes. Guards that telemetry (instance #1) is present and
    that the sort is honored, so the route loop / pins iterate a stable, ordered registry."""
    caps = catalog.load_capabilities()
    by_name = {c["name"]: c for c in caps}
    assert "telemetry" in by_name
    assert [c["name"] for c in caps] == sorted(by_name, key=lambda n: by_name[n]["order"])
    assert catalog.registered_capabilities() == [c["name"] for c in caps]


def test_telemetry_descriptor_has_every_field_the_shell_dispatches_over():
    """The shipped telemetry descriptor carries the full parameterization contract (the _REQUIRED_TOP /
    _REQUIRED_SUGGESTER keys). Guards the shared shell against a KeyError at dispatch: a descriptor that
    omitted, say, `enact_kind` or `block_shape` would crash the generic route, not just degrade telemetry."""
    tel = next(c for c in catalog.load_capabilities() if c["name"] == "telemetry")
    assert _REQUIRED_TOP <= set(tel), "missing: %s" % (_REQUIRED_TOP - set(tel))
    assert _REQUIRED_SUGGESTER <= set(tel["suggester"])
    assert tel["block_key"] == "metrics" and tel["block_shape"] == "list"
    assert tel["enact_kind"] == "prometheus_reload"


def test_telemetry_descriptor_wiring_is_real_not_vapor():
    """Every reference in the telemetry descriptor resolves to a real artifact: the suggester module imports
    and its suggest/declared names are callables, the named vector file exists, and the generator script
    exists. Guards the seam's worst failure mode — a descriptor pointing at a renamed function or an unwritten
    generator would pass a schema check but explode only when an operator opens the dialog."""
    tel = next(c for c in catalog.load_capabilities() if c["name"] == "telemetry")
    mod = importlib.import_module("kontroll.service." + tel["suggester"]["module"])
    assert callable(getattr(mod, tel["suggester"]["suggest"]))
    assert callable(getattr(mod, tel["suggester"]["declared"]))
    svc = importlib.import_module("kontroll.service." + tel["service"]["module"])
    assert callable(getattr(svc, "build_plan")) and callable(getattr(svc, "apply_plan"))
    assert os.path.exists(os.path.join(ROOT, "vectors", tel["vector"] + ".yml"))
    assert os.path.exists(os.path.join(ROOT, tel["generator"]["script"]))


def test_registry_is_drop_in(tmp_path, monkeypatch):
    """A capabilities/<cap>.yml dropped into the registry dir alone appears in registered_capabilities(),
    with no loader edit — the registry's own "add an X" proof. Guards the modularity invariant the seam
    rests on: registering a capability is a file drop, never a code change. (A bare README is ignored.)"""
    (tmp_path / "zztest.yml").write_text(
        yaml.safe_dump({"name": "zztest", "order": 99}), encoding="utf-8")
    (tmp_path / "README.md").write_text("# ignored", encoding="utf-8")
    monkeypatch.setattr(paths, "CAPABILITIES_DIR", str(tmp_path))
    assert catalog.registered_capabilities() == ["zztest"]


def test_missing_registry_dir_is_empty_not_an_error(tmp_path, monkeypatch):
    """An absent capabilities/ dir yields an empty registry (not an exception) — so the seam degrades to
    "no secondary capabilities", and the INVARIANT D* PRIMARY pin (which must survive an empty registry)
    has a real empty-registry case to lean on."""
    monkeypatch.setattr(paths, "CAPABILITIES_DIR", str(tmp_path / "does-not-exist"))
    assert catalog.load_capabilities() == []
    assert catalog.registered_capabilities() == []
