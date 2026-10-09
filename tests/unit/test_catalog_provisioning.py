"""catalog.module_provisioning — the READ side of the onboard provisioning-surface seam.

The blind-joe constraint says onboarding is IP+creds and any manual step beyond that (e.g. "grant the API
token the PVEAuditor role") must be SURFACED at onboarding, not buried in a doc. A device class declares those
prerequisites as shipped data (`modules/<key>/module.yml provisioning:`); this getter reads them BY COLLECTION
so both the onboard plan (prevent) and the validate seam's deferred role-map check (detect) share one datum.

These pin the load-bearing resolution contract — chiefly that it matches `collections[].name`, NOT the module
key — because at onboard time the only handle is the form slug, which is the collection-derived key, never the
shipped module key (community_proxmox/community.proxmox vs the shipped key `proxmox`). A path-join by key would
silently resolve to nothing: a useless feature that still reads green.
"""
import pytest
import yaml

from kontroll import catalog, paths

pytestmark = pytest.mark.unit


def _modtree(tmp_path, modules):
    """Write a synthetic modules/<key>/module.yml tree and point paths.MODULES_DIR at it. `modules` is
    {key: doc} — so a test controls the key/collection split (the whole point of the by-collection contract)."""
    root = tmp_path / "modules"
    for key, doc in modules.items():
        d = root / key
        d.mkdir(parents=True)
        (d / "module.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return root


def test_resolves_by_collection_name_not_key(tmp_path, monkeypatch):
    """The getter matches `collections[].name`, not the directory/module key. Guards the MF-3 blocker: the only
    handle at onboard time is the collection-derived slug, so a path-join by key would find nothing — this asserts
    a class keyed `proxmox` but collection `community.proxmox` is found by the COLLECTION and NOT by the key."""
    monkeypatch.setattr(paths, "MODULES_DIR", str(_modtree(tmp_path, {
        "proxmox": {"key": "proxmox", "collections": [{"name": "community.proxmox"}],
                    "provisioning": [{"grant": "PVEAuditor", "note": "grant it"}]},
    })))
    assert [r["grant"] for r in catalog.module_provisioning("community.proxmox")] == ["PVEAuditor"]
    assert catalog.module_provisioning("proxmox") == []          # the KEY must NOT resolve (scan-by-collection)


def test_class_without_a_provisioning_block_yields_empty(tmp_path, monkeypatch):
    """A class that declares no `provisioning:` (the universal case) yields [] — the feature is purely additive,
    needs no per-class registration, and never fabricates a prerequisite. Guards a regression where a missing
    block raised or returned a truthy sentinel that would render a spurious prerequisite at onboarding."""
    monkeypatch.setattr(paths, "MODULES_DIR", str(_modtree(tmp_path, {
        "cisco_ios": {"key": "cisco_ios", "collections": [{"name": "cisco.ios"}]},
    })))
    assert catalog.module_provisioning("cisco.ios") == []
    assert catalog.module_provisioning("no.such.collection") == []


def test_a_malformed_module_does_not_blank_a_sibling(tmp_path, monkeypatch):
    """A typo in ONE class's module.yml must not blank another class's prerequisites — the scan skips an
    unparseable file rather than aborting. Guards the failure mode where a single bad descriptor silently
    suppresses every other class's provisioning surface (a whole-fleet outage from one typo)."""
    root = _modtree(tmp_path, {
        "proxmox": {"key": "proxmox", "collections": [{"name": "community.proxmox"}],
                    "provisioning": [{"grant": "PVEAuditor", "note": "grant it"}]},
    })
    (root / "broken").mkdir()
    (root / "broken" / "module.yml").write_text("key: broken\n  : : bad yaml :\n", encoding="utf-8")
    monkeypatch.setattr(paths, "MODULES_DIR", str(root))
    assert [r["grant"] for r in catalog.module_provisioning("community.proxmox")] == ["PVEAuditor"]


def test_shipped_proxmox_class_surfaces_pveauditor():
    """The REAL shipped modules/proxmox/module.yml surfaces the PVEAuditor grant by its collection
    (community.proxmox). Guards the wired integration end: that the descriptor actually carries the block the
    onboard surface + the validate token-scope/A' check both depend on (the one declaration, two consumers)."""
    grants = [r["grant"] for r in catalog.module_provisioning("community.proxmox")]
    assert "PVEAuditor" in grants
