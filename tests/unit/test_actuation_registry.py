"""The actuation/<key>/unit.yml app-store unit registry (R2): the requirements-union + pin-conflict resolver
(gen-requirements.py), the fail-closed descriptor validator (gen-actuation.py), and the catalog loader.

WHY (the failures these guard):
  * resolve_pins must let an app-store EXACT '==' pin WIN over a module floor (else the deliberate, reviewed
    supply-chain pin is silently downgraded to 'anything >= X'), and must FAIL CLOSED on two different exact pins
    for one collection (no single install satisfies both) — report 21 §4.3. A fleet with NO units must derive a
    byte-identical lockfile (the R2 no-blast invariant: floors-only keeps the first, unchanged).
  * _actuation_collections must union ONLY active units whose target class is enabled (report 21 §3), so a
    disabled / orphaned unit never silently installs a collection.
  * validate_unit must reject a malformed descriptor (bad kind / floor-not-exact / key!=dir / unknown schema /
    non-enabled target / git source / standalone-with-install) BEFORE it unions a pin or anything installs it.
  * the catalog loader must read the instance overlay + skip the README, so the GUI/API see exactly the units.
"""
import copy
import importlib.util
import os

import pytest
import yaml

from kontroll import catalog, paths

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_script(modname, filename):
    """Load a hyphenated scripts/<filename> by path (not importable as a module name)."""
    spec = importlib.util.spec_from_file_location(modname, os.path.join(ROOT, "scripts", filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


genreq = _load_script("gen_requirements_r2", "gen-requirements.py")
genact = _load_script("gen_actuation_r2", "gen-actuation.py")

GOOD = {
    "schema": 1, "key": "good", "status": "active",
    "unit": {"kind": "collection_playbook", "collection": "cisco.ios", "name": "ios_facts"},
    "install": {"collections": [{"name": "cisco.ios", "version": "==8.0.4"}],
                "provenance": {"source": "galaxy", "signature": "required"}},
    "target": {"device_class": "cisco_ios", "inventory_group": "core_switch", "blast_radius": "LAN"},
}


def _write_unit(adir, key, **over):
    """Write a minimal valid unit.yml under <adir>/<key>/, overriding any top-level field via **over."""
    d = adir / key
    d.mkdir(parents=True)
    doc = copy.deepcopy(GOOD)
    doc["key"] = key
    doc.update(over)
    (d / "unit.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")


# ── resolve_pins (the supply-chain dedup policy) ───────────────────────────────────────────────────────────────
def test_resolve_pins_exact_wins_over_floor():
    """An actuation EXACT '==' pin replaces a module FLOOR for the same collection — the reviewed pin is never
    silently downgraded to the weaker floor."""
    out = genreq.resolve_pins([{"name": "cisco.ios", "version": ">=8.0.0"},
                               {"name": "cisco.ios", "version": "==8.0.4"}])
    assert out == [{"name": "cisco.ios", "version": "==8.0.4"}]


def test_resolve_pins_floors_only_keep_first_is_byte_identical():
    """No exact pins (a fleet of module floors) -> keep the FIRST per name, in order — so a unit-free fleet derives
    the same lockfile R2 inherited."""
    floors = [{"name": "community.sops", "version": ">=1.6.0"},
              {"name": "cisco.ios", "version": ">=8.0.0"},
              {"name": "cisco.ios", "version": ">=11.0.0"}]   # the 2nd cisco floor is dropped (keep-first)
    assert genreq.resolve_pins(floors) == floors[:2]


def test_resolve_pins_two_differing_exacts_fail_closed():
    """Two different exact pins for one collection have no common install -> SystemExit (the operator re-pins one)."""
    with pytest.raises(SystemExit):
        genreq.resolve_pins([{"name": "cisco.ios", "version": "==8.0.4"},
                             {"name": "cisco.ios", "version": "==8.1.0"}])


def test_resolve_pins_same_exact_twice_is_fine():
    """Two units pinning the SAME exact version coexist (one entry survives) — not a conflict."""
    out = genreq.resolve_pins([{"name": "cisco.ios", "version": "==8.0.4"},
                               {"name": "cisco.ios", "version": "==8.0.4"}])
    assert out == [{"name": "cisco.ios", "version": "==8.0.4"}]


def test_conflict_check_mode_is_resolve_only(monkeypatch):
    """`gen-requirements --conflict-check` (the FIX-M9 promote gate's detector) runs the pin RESOLUTION and returns
    clean when compute() succeeds / propagates the SystemExit when it fails closed (a `==` conflict) — and renders/
    writes NO lockfile (resolve-only). Guards that the gate neither writes the lockfile nor swallows a conflict."""
    monkeypatch.setattr(genreq, "_load", lambda rel: {"enabled_modules": []})
    monkeypatch.setattr(genreq.paths, "resolve", lambda rel: rel)
    monkeypatch.setattr(genreq.sys, "argv", ["gen-requirements.py", "--conflict-check"])
    rendered = []
    monkeypatch.setattr(genreq, "render_lockfile", lambda out: rendered.append("x") or "")   # must NOT run
    monkeypatch.setattr(genreq, "compute", lambda enabled, adir: ([], {}))
    genreq.main()                                             # clean → returns, nothing rendered/written
    assert rendered == []
    monkeypatch.setattr(genreq, "compute",
                        lambda enabled, adir: (_ for _ in ()).throw(SystemExit("pin conflict: cisco.ios")))
    with pytest.raises(SystemExit):
        genreq.main()                                        # a conflict propagates (the gate's non-zero exit)


# ── _actuation_collections (the §3 net-composition union) ──────────────────────────────────────────────────────
def test_actuation_collections_unions_active_enabled(tmp_path):
    """An active unit whose target class is enabled contributes its install.collections to the union."""
    _write_unit(tmp_path, "u-active")
    assert {"name": "cisco.ios", "version": "==8.0.4"} in genreq._actuation_collections(str(tmp_path), ["cisco_ios"])


def test_actuation_collections_skips_disabled(tmp_path):
    """A status: disabled unit contributes NO pin (the removal-without-deletion path)."""
    _write_unit(tmp_path, "u-disabled", status="disabled")
    assert genreq._actuation_collections(str(tmp_path), ["cisco_ios"]) == []


def test_actuation_collections_skips_non_enabled_target(tmp_path):
    """A unit targeting a class the fleet doesn't run contributes nothing (no orphaned install)."""
    _write_unit(tmp_path, "u-orphan")   # targets cisco_ios, which is NOT in the enabled list below
    assert genreq._actuation_collections(str(tmp_path), ["proxmox"]) == []


# ── validate_unit (fail-closed schema validation) ──────────────────────────────────────────────────────────────
def test_validate_unit_accepts_a_good_collection_playbook():
    """A well-formed collection_playbook unit validates clean."""
    assert genact.validate_unit(copy.deepcopy(GOOD), "good", ["cisco_ios"]) == []


def test_validate_unit_accepts_standalone_without_install():
    """A standalone (in-repo) unit needs a repo_playbook and NO install block — nothing to install."""
    doc = {"schema": 1, "key": "s", "unit": {"kind": "standalone", "repo_playbook": "ansible/playbooks/ping.yml"},
           "target": {"device_class": "cisco_ios"}}
    assert genact.validate_unit(doc, "s", ["cisco_ios"]) == []


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d.update(schema=99), "schema"),
    (lambda d: d["unit"].update(kind="arbitrary-command"), "kind"),                  # the closed-enum guard
    (lambda d: d["install"]["collections"][0].update(version=">=8.0.0"), "EXACT"),   # a floor where an exact is required
    (lambda d: d.update(key="different"), "directory name"),                          # key != dir
    (lambda d: d["install"]["provenance"].update(source="git"), "git"),              # git source rejected (MVP)
    (lambda d: d["target"].update(blast_radius="galaxy"), "blast_radius"),
])
def test_validate_unit_rejects_malformed(mutate, needle):
    """Each malformed descriptor is rejected with an error naming the offending field — a bad unit never reaches
    ansible-galaxy / never unions a pin."""
    doc = copy.deepcopy(GOOD)
    mutate(doc)
    errs = genact.validate_unit(doc, "good", ["cisco_ios"])
    assert any(needle in e for e in errs), errs


def test_validate_unit_rejects_non_enabled_target():
    """A unit targeting a non-enabled module fails closed (no install for a class the fleet doesn't run)."""
    errs = genact.validate_unit(copy.deepcopy(GOOD), "good", ["proxmox"])
    assert any("not an enabled module" in e for e in errs)


def test_validate_unit_rejects_standalone_with_install():
    """A standalone unit that carries an install block is incoherent (standalone installs nothing)."""
    doc = {"schema": 1, "key": "s", "unit": {"kind": "standalone", "repo_playbook": "ansible/playbooks/ping.yml"},
           "install": {"collections": [{"name": "x", "version": "==1.0.0"}]}, "target": {"device_class": "cisco_ios"}}
    assert any("NO install" in e for e in genact.validate_unit(doc, "s", ["cisco_ios"]))


def test_validate_all_collects_failures(tmp_path):
    """validate_all returns {dirkey: errors} for the failing units only (a good unit isn't reported)."""
    _write_unit(tmp_path, "ok")
    _write_unit(tmp_path, "bad", schema=99)
    failures = genact.validate_all(str(tmp_path), ["cisco_ios"])
    assert "bad" in failures and "ok" not in failures


def test_shipped_tree_has_no_invalid_actuation_units():
    """The committed/shipped tree carries no invalid actuation unit (the registry README is not a unit) — guards a
    future committed unit being malformed. enabled_modules=None skips the target check (shape-only)."""
    assert genact.validate_all(paths.resolve("actuation"), None) == {}


# ── validate_knobs (the R3 curated configure-form knob block) ──────────────────────────────────────────────────
def test_validate_knobs_accepts_a_curated_set():
    """A well-formed curated knob block (one per server-validated type) validates clean — the worked-extraction
    MVP configure surface (curated knobs, not argspec extraction)."""
    knobs = [{"key": "mode", "type": "enum", "allowed": ["fast", "safe"], "default": "safe"},
             {"key": "enabled", "type": "bool", "default": True},
             {"key": "retries", "type": "int", "range": {"min": 0, "max": 5}, "default": 3},
             {"key": "peer_ip", "type": "ipv4"},
             {"key": "peer_host", "type": "hostname"},
             {"key": "tag", "type": "text", "pattern": "[a-z]+", "default": "edge"}]
    assert genact.validate_knobs(knobs) == []


def test_validate_knobs_none_and_empty_are_valid():
    """A unit with NO knobs (None) or an empty list is valid — the block is optional (nothing to configure)."""
    assert genact.validate_knobs(None) == []
    assert genact.validate_knobs([]) == []


@pytest.mark.parametrize("knob,needle", [
    ({"key": "pw", "type": "secret"}, "forbidden"),                       # SEC-2: no secret actuation var
    ({"key": "pw", "type": "password"}, "forbidden"),
    ({"key": "free", "type": "text"}, "pattern"),                         # text needs a pattern (fail-closed)
    ({"key": "pick", "type": "enum"}, "allowed"),                         # enum needs a non-empty allow-list
    ({"key": "x", "type": "wat"}, "must be one of"),                      # unknown type
    ({"key": "n", "type": "int", "range": {"min": 9, "max": 1}}, "above range.max"),
    ({"key": "Bad-Key", "type": "bool"}, "key must match"),               # uppercase/hyphen not allowed
    ({"key": "p", "type": "int", "range": {"min": 1, "max": 10}, "default": 99}, "default is invalid"),
    ({"key": "m", "type": "enum", "allowed": ["a"], "default": "z"}, "default is invalid"),
])
def test_validate_knobs_rejects_malformed(knob, needle):
    """Each malformed knob is rejected with an error naming the fault — a bad lever never renders / never reaches
    the server validator as a surprise. Covers the secret-forbidden (SEC-2), text-needs-pattern, enum-needs-
    allowed, closed-type, int-range, key-shape, and curated-default-must-validate rules."""
    errs = genact.validate_knobs([knob])
    assert any(needle in e for e in errs), errs


def test_validate_knobs_rejects_duplicate_key():
    """Two knobs with the same key are rejected (the configure form harvests by key — a dup would silently
    shadow)."""
    errs = genact.validate_knobs([{"key": "dup", "type": "bool"}, {"key": "dup", "type": "bool"}])
    assert any("duplicated" in e for e in errs)


def test_validate_unit_folds_knob_errors_in(tmp_path):
    """validate_unit surfaces a malformed knob through the unit's own error list — so gen-actuation --check (and
    tests/validate) fails closed on a bad curated knob exactly as it does on a bad install pin."""
    doc = copy.deepcopy(GOOD)
    doc["knobs"] = [{"key": "free", "type": "text"}]                      # missing pattern
    errs = genact.validate_unit(doc, "good", ["cisco_ios"])
    assert any("pattern" in e for e in errs)


# ── never-brick trust sidecar + the Tier-cap (R5 PR-B) ─────────────────────────────────────────────────────────
def test_sidecar_defaults_every_module_collection_to_adaptive():
    """A module-derived collection (no provenance) renders signature_policy: adaptive + sha256: null in the trust
    sidecar — the brick-proof default-on-absence (NB-1): no operator action makes the fleet 'required'. Guards a
    `+`-flag/strict default sneaking onto the fleet path and bricking an install from an unsigned source."""
    out = [{"name": "community.sops", "version": ">=1.6.0"}, {"name": "cisco.ios", "version": ">=8.0.0"}]
    doc = yaml.safe_load(genreq.render_sidecar(out, {}, "adaptive", genreq.DEFAULT_KEYRING))
    assert doc["default_signature_policy"] == "adaptive"
    for c in doc["collections"]:
        assert c["signature_policy"] == "adaptive" and c["sha256"] is None    # NB-1 + BRICK-3 (floor => null sha256)


def test_sidecar_attaches_a_unit_required_policy_and_sha256(tmp_path):
    """A unit declaring signature: required (+ an optional sha256) attaches that policy to ITS collection in the
    sidecar; a module collection alongside stays adaptive. Guards the per-unit opt-in ratchet riding the generated
    sidecar (never the lockfile, which stays policy-free)."""
    digest = "a" * 64
    _write_unit(tmp_path, "u-req", install={"collections": [{"name": "cisco.ios", "version": "==8.0.4"}],
                "provenance": {"source": "galaxy", "signature": "required", "sha256": digest}})
    prov = genreq._actuation_provenance(str(tmp_path), ["cisco_ios"])
    assert prov["cisco.ios"] == {"signature_policy": "required", "keyring": None, "sha256": digest}
    out = [{"name": "cisco.ios", "version": "==8.0.4"}, {"name": "community.sops", "version": ">=1.6.0"}]
    by = {c["name"]: c for c in yaml.safe_load(
        genreq.render_sidecar(out, prov, "adaptive", genreq.DEFAULT_KEYRING))["collections"]}
    assert by["cisco.ios"]["signature_policy"] == "required" and by["cisco.ios"]["sha256"] == digest
    assert by["community.sops"]["signature_policy"] == "adaptive" and by["community.sops"]["sha256"] is None


def test_sidecar_render_is_deterministic():
    """render_sidecar is a pure function of its inputs — two renders are byte-identical (the --check staleness gate
    relies on determinism; a non-deterministic generator would flap red for no real drift)."""
    out = [{"name": "cisco.ios", "version": ">=8.0.0"}]
    assert (genreq.render_sidecar(out, {}, "adaptive", genreq.DEFAULT_KEYRING)
            == genreq.render_sidecar(out, {}, "adaptive", genreq.DEFAULT_KEYRING))


def test_gen_requirements_makes_no_network_call():
    """BRICK-1 (the brick-hunter's blocker): the lockfile/sidecar generator gates every install AND runs in the
    hermetic tests/validate, so it MUST stay offline — a network GET there would brick on a Galaxy blip / an
    air-gapped node. Pin it by source: no http/urllib/requests/socket primitive appears. The recorded sha256 is
    captured by the install WRAPPER, not here (synthesis Decision R1)."""
    with open(os.path.join(ROOT, "scripts", "gen-requirements.py"), encoding="utf-8") as fh:
        src = fh.read()
    for tok in ("import urllib", "import requests", "import httpx", "import socket", "urlopen", "http.client"):
        assert tok not in src, "gen-requirements.py must make no network call (BRICK-1) — found %r" % tok


def test_validate_unit_accepts_adaptive_signature():
    """signature: adaptive is a valid enum value (the brick-proof default made explicit) — a unit may declare it on
    a low-blast target without the Tier-cap firing."""
    doc = copy.deepcopy(GOOD)
    doc["install"]["provenance"]["signature"] = "adaptive"
    doc["target"]["inventory_group"] = "leaf_switch"     # a low-blast group (not edge/core)
    assert genact.validate_unit(doc, "good", ["cisco_ios"]) == []


def test_validate_unit_tier_caps_unverified_high_blast():
    """A unit targeting core_switch/edge_firewall with signature != required is REJECTED at generate (the Tier-cap,
    NB-4): unverified provenance may not reach the highest-blast tier. Guards a novice pointing an unsigned download
    at the firewall / core switch."""
    doc = copy.deepcopy(GOOD)                            # GOOD targets core_switch
    doc["install"]["provenance"]["signature"] = "adaptive"
    assert any("highest-blast tier" in e for e in genact.validate_unit(doc, "good", ["cisco_ios"]))


def test_validate_unit_tier_cap_fires_on_absent_signature():
    """The Tier-cap uses the EFFECTIVE policy: an OMITTED signature defaults to adaptive, so a high-blast unit that
    simply leaves signature off is still rejected (absence != required) — the brick-proof default can't smuggle
    unverified content onto edge/core."""
    doc = copy.deepcopy(GOOD)
    doc["install"]["provenance"].pop("signature", None)
    assert any("highest-blast tier" in e for e in genact.validate_unit(doc, "good", ["cisco_ios"]))


def test_validate_unit_allows_adaptive_on_low_blast_target():
    """adaptive/absent provenance on a LOW-blast target is fine — the Tier-cap fires only on the dangerous
    COMBINATION (high-blast + unverified), never on plain absence (NB-1)."""
    doc = copy.deepcopy(GOOD)
    doc["install"]["provenance"].pop("signature", None)
    doc["target"]["inventory_group"] = "docker_hosts"
    assert genact.validate_unit(doc, "good", ["cisco_ios"]) == []


def test_validate_unit_rejects_bad_sha256_shape():
    """A present-but-malformed provenance.sha256 (not 64-hex) is rejected; absence is valid (NB-1). Guards a typo'd
    digest reaching the wrapper's L2b re-verify as a guaranteed mismatch."""
    doc = copy.deepcopy(GOOD)
    doc["install"]["provenance"]["sha256"] = "not-a-digest"
    assert any("64-hex digest" in e for e in genact.validate_unit(doc, "good", ["cisco_ios"]))


# ── catalog loader (the instance-overlay registry read API) ────────────────────────────────────────────────────
def test_catalog_loads_units_from_instance_overlay(tmp_path, monkeypatch):
    """load_actuation_units reads instance/actuation/<key>/unit.yml via the overlay and skips the shipped README;
    registered_actuation_units is the neutral keys seam a route loop iterates."""
    monkeypatch.setattr(paths, "ROOT", str(tmp_path))
    (tmp_path / "actuation").mkdir()
    (tmp_path / "actuation" / "README.md").write_text("doc, not a unit\n", encoding="utf-8")
    _write_unit(tmp_path / "instance" / "actuation", "real-unit")
    assert catalog.registered_actuation_units() == ["real-unit"]
    assert catalog.actuation_unit("real-unit")["unit"]["collection"] == "cisco.ios"
