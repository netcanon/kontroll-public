"""Shallow-search redesign — the fast default + the accuracy guarantee (docs/api-architecture.md §10).

/search returns SHALLOW local records by default (files only, no ansible-doc) and defers the deep
capability classification to deep_probe / GET /probe. These tests pin the TWO-AXIS accuracy property:

  * DEPTH axis (proved here, hermetically): a shallow capability cell equals the deep cell EXCEPT where a
    `module_option` rule decides it — there shallow honestly reads 'maybe', never a flipped yes/no. That is
    shallow ⊑ deep in the three-valued information order: the fast search can only ever DEFER, never lie.
  * SOURCE axis (verified live by service_search_parity over the real fleet): walking plugins/ reproduces
    ansible-doc's module/plugin signals. test_search_parity_* pin that the verifier flags a divergence.

The single systematic shallow→deep difference is backup-via-a-*_config-module's-`backup:`-option — the one
signal that needs the per-module doc parse. Everything else (cliconf/httpapi/netconf plugins, *_config/
_facts/_resource module suffixes) is visible in the files, so shallow == deep on it.
"""
import json
import os

import pytest

from kontroll import catalog, probe, record
from kontroll.service.search import service_search, service_search_parity

pytestmark = pytest.mark.unit


def _touch(path):
    with open(path, "w", encoding="utf-8"):
        pass


def _make_collection(base, coll, *, modules=(), plugins=None, description="", tags=()):
    """Lay down a minimal INSTALLED-collection tree (MANIFEST.json + plugins/<type>/<name>.py) under
    base/<ns>/<name> — the on-disk shape shallow_from_local reads. An __init__.py is planted in each
    plugin dir to assert it is skipped (it is not a module/plugin)."""
    ns, name = coll.split(".", 1)
    cdir = os.path.join(base, ns, name)
    mdir = os.path.join(cdir, "plugins", "modules")
    os.makedirs(mdir)
    with open(os.path.join(cdir, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump({"collection_info": {"namespace": ns, "name": name, "version": "1.2.3",
                                       "description": description, "tags": list(tags)}}, fh)
    _touch(os.path.join(mdir, "__init__.py"))
    for m in modules:
        _touch(os.path.join(mdir, m + ".py"))
    for ptype, names in (plugins or {}).items():
        pdir = os.path.join(cdir, "plugins", ptype)
        os.makedirs(pdir)
        _touch(os.path.join(pdir, "__init__.py"))
        for n in names:
            _touch(os.path.join(pdir, n + ".py"))
    return base


# --- the prober: files -> facts, no ansible-doc ----------------------------- #
def test_shallow_from_local_reads_signals_from_files(tmp_path):
    """shallow_from_local derives modules + plugins from the collection's files (no ansible-doc), skips
    __init__, and pulls description/tags from MANIFEST.json — the fast local probe the redesigned /search
    uses by default. module_options stays {} (the deep-only signal stays deferred -> 'maybe')."""
    base = _make_collection(str(tmp_path), "cisco.ios", modules=["ios_command", "ios_config"],
                            plugins={"cliconf": ["ios"]}, description="Cisco IOS", tags=["cisco", "ios"])
    f = probe.shallow_from_local("cisco.ios", "1.2.3", base)
    assert f["depth"] == "shallow" and f["origin"] == "local"
    assert f["modules"] == ["ios_command", "ios_config"]        # sorted; __init__ skipped
    assert f["plugins"] == {"cliconf": ["ios"]}
    assert f["module_options"] == {}                            # never read shallow — the deferred signal
    assert f["description"] == "Cisco IOS" and f["tags"] == ["cisco", "ios"]


def test_shallow_from_local_missing_tree_is_empty_not_error(tmp_path):
    """A collection with no MANIFEST and no plugins/ tree (an odd/roles-only layout) shallow-probes to
    empty signals rather than raising — so local_shallow never crashes a search on a surprise layout."""
    (tmp_path / "acme" / "bare").mkdir(parents=True)
    f = probe.shallow_from_local("acme.bare", "1.0.0", str(tmp_path))
    assert f["modules"] == [] and f["plugins"] == {} and f["description"] == ""


# --- the SOUNDNESS THEOREM: shallow never contradicts deep ------------------ #
# A grid of synthetic deep facts spanning the predicate signal space; the shallow view of each is the
# same facts with module_options dropped (exactly what shallow_from_local yields, given source-axis parity).
_SIGNAL_GRID = [
    {"plugins": {"cliconf": ["x"]}, "modules": ["a_config"], "module_options": {"a_config": ["backup"]}},
    {"plugins": {"httpapi": ["x"]}, "modules": ["a_facts"], "module_options": {}},
    {"plugins": {}, "modules": ["a_config"], "module_options": {"a_config": ["backup"]}},   # backup ONLY via option
    {"plugins": {}, "modules": ["a_config"], "module_options": {"a_config": ["other"]}},    # _config, no backup opt
    {"plugins": {}, "modules": ["a_resource"], "module_options": {}},
    {"plugins": {"netconf": ["x"]}, "modules": [], "module_options": {}},
    {"plugins": {}, "modules": ["plain_module"], "module_options": {}},                     # nothing -> bespoke
    {"plugins": {}, "modules": [], "module_options": {}},                                   # empty
]


@pytest.mark.parametrize("sig", _SIGNAL_GRID)
def test_shallow_is_sound_wrt_deep(sig, make_facts, vectors):
    """THEOREM (depth axis): for EVERY capability cell, the shallow state never CONTRADICTS the deep state —
    it is identical or a 'maybe' where deep is definite (shallow ⊑ deep). A yes↔no flip would mean the fast
    search lies about a capability; this proves it can only DEFER. Spans cliconf/httpapi/netconf, the
    *_config/_facts/_resource suffixes, and the module_option-backup signal present/absent."""
    deep = make_facts(**sig)
    shallow = make_facts(**{**sig, "module_options": {}, "depth": "shallow"})
    drec = record.build_record(deep, vectors)
    srec = record.build_record(shallow, vectors)
    for v in vectors:
        ds = drec["capabilities"][v["name"]]["state"]
        ss = srec["capabilities"][v["name"]]["state"]
        assert ss == ds or ss == "maybe", (
            "vector %s: shallow=%s contradicts deep=%s (must agree or defer to 'maybe')" % (v["name"], ss, ds))


def test_backup_via_config_option_defers_to_maybe_when_shallow(make_facts, vectors):
    """The ONE deep-only signal — backup via a *_config module's `backup:` option — reads 'yes' at deep
    depth but honestly DEFERS to 'maybe' at shallow depth (no cliconf/_facts shortcut present). This single
    cell is the systematic shallow→deep difference; GET /probe (or --deep) resolves it."""
    sig = dict(plugins={}, modules=["ios_config"], module_options={"ios_config": ["backup"]})
    deep = make_facts(**sig)
    shallow = make_facts(plugins={}, modules=["ios_config"], module_options={}, depth="shallow")
    assert record.build_record(deep, vectors)["capabilities"]["backup"]["state"] == "yes"
    assert record.build_record(shallow, vectors)["capabilities"]["backup"]["state"] == "maybe"


# --- service_search: shallow default, deep opt-in --------------------------- #
def test_service_search_default_is_shallow_no_deep_probe(monkeypatch, make_facts, vectors):
    """The DEFAULT search returns SHALLOW local records and never calls deep_probe — the perf win (a broad
    keyword no longer triggers an ansible-doc fan-out). deep_probe wired to explode is never reached."""
    monkeypatch.setattr(catalog, "local_shallow",
                        lambda kw, limit: [make_facts(collection="cisco.ios", depth="shallow",
                                                      plugins={"cliconf": ["ios"]}, modules=["ios_command"])])
    monkeypatch.setattr(catalog, "galaxy_search", lambda kw, limit: [])

    def boom(*a, **k):
        raise AssertionError("shallow search must not deep_probe")
    monkeypatch.setattr(probe, "deep_probe", boom)
    recs = service_search(["cisco"], origin="local", vectors=vectors)
    assert [r["collection"] for r in recs] == ["cisco.ios"] and recs[0]["depth"] == "shallow"


def test_service_search_deep_reprobes_and_resolves_maybe(monkeypatch, make_facts, vectors):
    """deep=True re-probes the shallow candidates via deep_probe — the opt-in that resolves '?' cells. The
    returned record carries depth=deep and the resolved capability (here backup, provable only at depth)."""
    monkeypatch.setattr(catalog, "local_shallow",
                        lambda kw, limit: [make_facts(collection="cisco.ios", depth="shallow", modules=["ios_config"])])
    monkeypatch.setattr(catalog, "galaxy_search", lambda kw, limit: [])
    monkeypatch.setattr(probe, "deep_probe",
                        lambda coll, version=None: make_facts(collection=coll, modules=["ios_config"],
                                                              module_options={"ios_config": ["backup"]}))
    recs = service_search(["cisco"], origin="local", deep=True, vectors=vectors)
    assert recs[0]["depth"] == "deep"
    assert recs[0]["capabilities"]["backup"]["state"] == "yes"      # deep resolved the module_option signal


def test_service_search_vector_filter_forces_deep_no_false_negative(monkeypatch, make_facts, vectors):
    """A `vector` filter implies deep — otherwise a capability provable only at depth (backup via the config
    option) would be a shallow 'maybe' and be wrongly filtered out. With deep forced, the backup-capable
    collection SURVIVES a vector=backup filter: the accuracy guarantee at the service boundary."""
    monkeypatch.setattr(catalog, "local_shallow",
                        lambda kw, limit: [make_facts(collection="cisco.ios", depth="shallow", modules=["ios_config"])])
    monkeypatch.setattr(catalog, "galaxy_search", lambda kw, limit: [])
    called = {"deep": False}

    def deep_probe(coll, version=None):
        called["deep"] = True
        return make_facts(collection=coll, modules=["ios_config"], module_options={"ios_config": ["backup"]})
    monkeypatch.setattr(probe, "deep_probe", deep_probe)
    recs = service_search(["cisco"], vector=["backup"], vectors=vectors)
    assert called["deep"] and [r["collection"] for r in recs] == ["cisco.ios"]


def test_local_shallow_caps_fanout_at_limit(monkeypatch):
    """catalog.local_shallow caps the shallow-probe fan-out at `limit` even when many collections match —
    the bound that (with shallow being cheap) keeps a broad keyword fast. The installed-list + per-file
    prober seams are stubbed so only the cap/keyword logic is exercised, no real collections."""
    many = {"/p": {"cisco.c%02d" % i: {"version": "1.0.0"} for i in range(30)}}
    monkeypatch.setattr(catalog, "_installed_json", lambda: many)
    monkeypatch.setattr(probe, "shallow_from_local", lambda coll, version, base: {"collection": coll})
    out = catalog.local_shallow(["cisco"], 8)
    assert len(out) == 8 and all(o["collection"].startswith("cisco.c") for o in out)


# --- service_search_parity: the live accuracy verifier ---------------------- #
def test_search_parity_flags_deferred_not_unsound(monkeypatch, make_facts, vectors):
    """service_search_parity classifies a shallow 'maybe' vs deep-definite cell as DEFERRED (honest) and
    reports 0 UNSOUND — the machine-checkable 'fast search is accurate vs the full probe'. Here the
    backup-via-config-option collection defers backup shallow and resolves it deep: deferred>=1, unsound=0."""
    monkeypatch.setattr(catalog, "local_shallow",
                        lambda kw, limit: [make_facts(collection="cisco.ios", depth="shallow", modules=["ios_config"])])
    monkeypatch.setattr(probe, "deep_probe",
                        lambda coll, version=None: make_facts(collection=coll, modules=["ios_config"],
                                                              module_options={"ios_config": ["backup"]}))
    res = service_search_parity(["cisco"], vectors=vectors)
    assert res["summary"]["unsound"] == 0 and res["summary"]["deferred"] >= 1
    backup = next(r for r in res["collections"] if r["vector"] == "backup")
    assert backup["shallow"] == "maybe" and backup["deep"] == "yes" and backup["verdict"] == "deferred"


def test_search_parity_detects_a_contradiction(monkeypatch, make_facts, vectors):
    """If shallow and deep ever DISAGREE on yes vs no (a source-axis divergence — file-walk seeing a signal
    ansible-doc doesn't, or vice versa), parity flags it UNSOUND. Pins that the verifier actually catches a
    flip, so a green parity run over the real fleet is meaningful, not vacuous."""
    monkeypatch.setattr(catalog, "local_shallow",
                        lambda kw, limit: [make_facts(collection="x.y", depth="shallow", plugins={"cliconf": ["z"]})])
    monkeypatch.setattr(probe, "deep_probe", lambda coll, version=None: make_facts(collection=coll))
    res = service_search_parity(["x"], vectors=vectors)
    assert res["summary"]["unsound"] >= 1
    actuate = next(r for r in res["collections"] if r["vector"] == "actuate")
    assert actuate["verdict"] == "unsound" and actuate["shallow"] == "yes" and actuate["deep"] == "no"
