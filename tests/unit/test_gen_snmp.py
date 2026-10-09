"""scripts/gen-snmp.py — the snmp_exporter `if_mib` module, GENERATED from a committed generator.yml + a
vendored public MIB closure into prometheus/exporters/snmp/modules.generated.yml, replacing the hand-authored
block in snmp.yml.j2 (no-bespoke-config tenet: derive the OID set from public IETF MIBs, pinned + --check-gated).

These pin the FAITHFUL MIGRATION (behaviour-preserving): the generated `if_mib` must reproduce EXACTLY the
6-metric / 7-OID shape the hand-authored snmp.yml.j2 scraped today — same OIDs + types, sysUpTime as a bare
scalar, the raw ifIndex index KEPT, a SINGLE ifName lookup, and ifName/ifDescr/ifAlias/ifType ABSENT as metrics.
The oracle is a FROZEN LITERAL transcribed from snmp.yml.j2:18-87 (NOT a parse of the .j2 — this change edits
the .j2, so a frozen oracle is the stable target). The comparison is SEMANTIC (name/oid/type/index/lookup) and
deliberately IGNORES `help:` — the generator emits help strings the hand-authored file lacked, so byte-equality
to the .j2 is impossible and is not the contract; series identity (metrics + labels) is. Guards the exact
failures the adversary review caught: an extra lookup adding ifDescr/ifAlias labels (series-identity break), a
broad walk pulling surplus metrics, the v0.28.0 sysUpTime eviction, and an enum stateset shape vs gauge.
"""
import importlib.util
import os

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytestmark = pytest.mark.unit

# The FROZEN oracle — transcribed from prometheus/exporters/snmp/snmp.yml.j2:18-87 (the hand-authored block this
# change replaces). {metric_name: (oid, type, frozenset(index_labelnames), frozenset(lookup_labelnames))}.
ORACLE = {
    "sysUpTime":     ("1.3.6.1.2.1.1.3",         "gauge",   frozenset(),          frozenset()),
    "ifAdminStatus": ("1.3.6.1.2.1.2.2.1.7",     "gauge",   frozenset({"ifIndex"}), frozenset({"ifName"})),
    "ifOperStatus":  ("1.3.6.1.2.1.2.2.1.8",     "gauge",   frozenset({"ifIndex"}), frozenset({"ifName"})),
    "ifHCInOctets":  ("1.3.6.1.2.1.31.1.1.1.6",  "counter", frozenset({"ifIndex"}), frozenset({"ifName"})),
    "ifHCOutOctets": ("1.3.6.1.2.1.31.1.1.1.10", "counter", frozenset({"ifIndex"}), frozenset({"ifName"})),
    "ifHighSpeed":   ("1.3.6.1.2.1.31.1.1.1.15", "gauge",   frozenset({"ifIndex"}), frozenset({"ifName"})),
}
# Names that must NOT appear as METRICS — ifName is a label (the lookup target), the others were never scraped.
ABSENT_METRICS = {"ifName", "ifDescr", "ifAlias", "ifType"}
IFNAME_LOOKUP_OID = "1.3.6.1.2.1.31.1.1.1.1"
MODULES_GENERATED = os.path.join(ROOT, "prometheus", "exporters", "snmp", "modules.generated.yml")


def _gen():
    spec = importlib.util.spec_from_file_location("gen_snmp", os.path.join(ROOT, "scripts", "gen-snmp.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _if_mib_metrics():
    """The generated modules.if_mib metrics, keyed by name (the unit under test)."""
    with open(MODULES_GENERATED, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    metrics = cfg["modules"]["if_mib"]["metrics"]
    return {m["name"]: m for m in metrics}


def test_if_mib_reproduces_the_seven_oid_oracle():
    """The generated modules.if_mib exposes EXACTLY the 6 metrics / 7 OIDs the hand-authored snmp.yml.j2 scraped
    (sysUpTime + ifAdminStatus/ifOperStatus/ifHCInOctets/ifHCOutOctets/ifHighSpeed), each with the SAME OID and
    type (counters for the ifHC* objects, gauge for the rest). Guards a behaviour-preserving migration: an
    extra/missing OID, or a type flip (e.g. an enum rendered as a stateset), silently changes the scrape — and
    the v0.28.0 sysUpTime eviction (MF3) would drop it from a naive stock if_mib."""
    metrics = _if_mib_metrics()
    assert set(metrics) == set(ORACLE), (
        "metric-name set drifted from the oracle (extra/missing metric changes the scrape): %s"
        % sorted(set(metrics) ^ set(ORACLE)))
    for name, (oid, mtype, _idx, _lk) in ORACLE.items():
        assert metrics[name]["oid"] == oid, "%s OID changed -> different object scraped" % name
        assert metrics[name]["type"] == mtype, (
            "%s type changed (expected %s) -> series semantics change (counter vs gauge / stateset)"
            % (name, mtype))


def test_if_mib_indexes_and_ifname_lookups_are_faithful():
    """Each interface metric keeps the raw ifIndex index AND exactly ONE ifName lookup (oid 1.3.6.1.2.1.31.1.1.1.1,
    DisplayString) — and sysUpTime is a bare scalar with no index/lookup. Guards the adversary's MF1: stock if_mib
    declares THREE lookups (ifName/ifDescr/ifAlias); adding ifDescr/ifAlias would put extra labels on every
    interface series and break series identity (dashboard/query continuity). The per-series label set must be
    EXACTLY {ifIndex, ifName}."""
    metrics = _if_mib_metrics()
    for name, (_oid, _type, want_idx, want_lk) in ORACLE.items():
        m = metrics[name]
        got_idx = frozenset(i["labelname"] for i in m.get("indexes", []))
        got_lk = frozenset(lk["labelname"] for lk in m.get("lookups", []))
        assert got_idx == want_idx, "%s index labels drifted: %s != %s" % (name, set(got_idx), set(want_idx))
        assert got_lk == want_lk, (
            "%s lookup labels drifted: %s != %s (an extra lookup changes every series' label set)"
            % (name, set(got_lk), set(want_lk)))
        for lk in m.get("lookups", []):
            if lk["labelname"] == "ifName":
                assert lk["oid"] == IFNAME_LOOKUP_OID and lk["type"] == "DisplayString", \
                    "the ifName lookup must resolve oid %s as DisplayString" % IFNAME_LOOKUP_OID


def test_absent_metrics_are_not_emitted():
    """ifName (a label, not a metric), ifDescr, ifAlias, and ifType must NOT appear as metrics. Guards a broad
    table walk (MF2') or stock lookups/overrides (MF1) leaking surplus series the hand-authored config never had."""
    metrics = _if_mib_metrics()
    leaked = ABSENT_METRICS & set(metrics)
    assert not leaked, "surplus metric(s) emitted that the hand-authored scrape never had: %s" % sorted(leaked)


def test_generated_file_is_modules_only_and_carries_no_secret():
    """The committed modules.generated.yml contains ONLY a top-level `modules:` mapping — NO `auths:` and no
    credential field name (username/password/community/priv_password). The snmp_exporter generator copies auths:
    verbatim into its output (incl. our throwaway generator.yml stub), so gen-snmp.py must strip it; this is the
    SEC1 guard that the SNMPv3 USM creds can never reach the committed/public artifact (they are SOPS-templated
    into the gitignored snmp.yml at deploy instead)."""
    with open(MODULES_GENERATED, encoding="utf-8") as fh:
        text = fh.read()
    cfg = yaml.safe_load(text)
    assert set(cfg) == {"modules"}, "committed artifact must be modules-only (auths must be stripped): %s" % sorted(cfg)
    # Scan the PARSED data (re-dumped, comment-free) so the header's prose ("no auths:") isn't a false positive;
    # the structural check above already proves there is no auths: block.
    data = yaml.safe_dump(cfg).lower()
    for field in ("auths", "username", "password", "community", "priv_password"):
        assert field not in data, "credential/auth token %r leaked into the public modules artifact" % field


def test_module_name_is_if_mib_for_zero_spine_edits():
    """The generated module's top-level key is `if_mib` — the closed allow-list (telemetry/snmp.yml
    params.module.allowed:[if_mib]) and the cisco_ios/fortigate {module: if_mib} selectors all key off this name.
    A rename would 404 every device scrape (?module=if_mib hits a missing module) with no spine error."""
    with open(MODULES_GENERATED, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    assert "if_mib" in cfg["modules"], "the generated module must stay named if_mib (allow-list + selector coupling)"


def test_check_mode_passes_when_committed_artifact_is_present_and_clean():
    """`gen-snmp.py --check` returns 0 for a present, modules-only, secret-free committed artifact — the
    generated-never-hand-maintained + no-secret staleness gate (binary-free, so it runs in the CI-only validator
    tier and this hermetic pytest twin). The byte-exact 'matches a fresh rebuild' gate is the dedicated CGO CI job."""
    assert _gen().main(["--check"]) == 0
