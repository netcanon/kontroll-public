"""logging/<method>.yml registry + vectors/logging.yml + capabilities/logging.yml — the drop-in registry, the
weak detection vector, and the capability descriptor's real wiring. Guards the registry "add an X" contract,
the C12 no-secret-label rule on every method descriptor, and a descriptor that passes schema but explodes when
the operator opens the dialog (vapor wiring).
"""
import os

import pytest

from kontroll import catalog, paths

pytestmark = pytest.mark.unit

# the Vector source types gen-logging knows how to render; a typo'd/Prometheus-shaped kind would not generate.
_KNOWN_KINDS = {"journald", "file", "docker_logs", "syslog", "http_client", "http_server", "socket", "exec"}
# the canonical, low-cardinality, NON-SECRET Loki label set (C12).
_CANONICAL_LABELS = {"source", "host", "service", "level", "run_id", "device"}


def test_registry_loads_and_sorts_by_order():
    """catalog.load_logging() discovers logging/<method>.yml drop-ins and returns them sorted by `order`
    (syslog_push, journald_remote, rest_pull, file_tail_ssh, proxmox_api) with no loader edit — the registry
    "add an X" contract (mirror of the telemetry-method registry). proxmox_api (order 5) is the concrete
    credentialed-pull instance; its appearance here WITHOUT a loader change is the drop-in proof."""
    methods = catalog.load_logging()
    names = [m["name"] for m in methods]
    assert names == ["syslog_push", "journald_remote", "rest_pull", "file_tail_ssh", "proxmox_api"]


def test_each_method_declares_a_known_vector_source_kind():
    """Every logging method's `kind` is a real Vector source type and names a wiring role or null — guards a
    typo'd/Prometheus-shaped kind gen-logging can't render, and an undeclared direction."""
    for m in catalog.load_logging():
        assert m["kind"] in _KNOWN_KINDS, "%s has unknown kind %r" % (m["name"], m["kind"])
        assert m["direction"] in ("push", "pull")


def test_no_method_descriptor_carries_a_secret_keyed_label():
    """No logging/<method>.yml `labels:` entry is outside the canonical NON-SECRET set — the C12 hard label
    rule. Guards a Loki stream label leaking a credential into the unencrypted index (the security pin V1
    bolded; T9)."""
    for m in catalog.load_logging():
        bad = set(m.get("labels") or []) - _CANONICAL_LABELS
        assert not bad, "%s emits non-canonical/secret-risk label(s) %s" % (m["name"], bad)


def test_logging_vector_loads_and_is_weak():
    """vectors/logging.yml loads, sorts after telemetry (order 5), and every match rule is LOW confidence —
    never high/medium, since 'has logs' is near-universal and mostly a host/runtime fact, not a collection
    signal (FLAG-1). Guards a strong logging claim that would over-suggest."""
    vecs = catalog.load_vectors()
    names = [v["name"] for v in vecs]
    assert names.index("logging") == names.index("telemetry") + 1
    logging_vec = next(v for v in vecs if v["name"] == "logging")
    assert all(r.get("confidence") == "low" for r in logging_vec.get("match") or [])


def test_logging_descriptor_wiring_is_real_not_vapor():
    """capabilities/logging.yml's suggester/service references resolve to real callables and its vector +
    generator exist on disk — guards the seam's worst failure: a descriptor that passes schema but explodes
    when the operator opens the dialog (mirror of the telemetry descriptor-wiring pin)."""
    import importlib
    d = next(c for c in catalog.load_capabilities() if c["name"] == "logging")
    mod = importlib.import_module("kontroll.service." + d["suggester"]["module"])
    assert callable(getattr(mod, d["suggester"]["suggest"])) and callable(getattr(mod, d["suggester"]["declared"]))
    svc = importlib.import_module("kontroll.service." + d["service"]["module"])
    assert callable(svc.build_plan) and callable(svc.apply_plan) and callable(svc.offerable_methods)
    assert os.path.exists(os.path.join(paths.VECTORS_DIR, "logging.yml"))
    assert os.path.exists(os.path.join(paths.ROOT, d["generator"]["script"]))


def test_registry_includes_logging_after_backup():
    """registered_capabilities() includes `logging` at its order 30 (after telemetry 10, backup 20) once the
    descriptor drops in — the drop-in proof; guards a loader edit being needed to register the capability."""
    caps = catalog.registered_capabilities()
    assert "logging" in caps and caps.index("logging") == caps.index("backup") + 1


def test_offerable_methods_carry_secret_domain_for_the_cred_prereq():
    """G3 (public-readiness audit 2026-06-18): the capability dialog now surfaces a method's credential
    prerequisite, so EVERY offerable method (logging AND telemetry) must expose `secret_domain` — None when the
    method needs no SOPS cred (syslog_push/journald_remote/host_node/blackbox), the domain NAME otherwise
    (file_tail_ssh -> logging_file_tail, rest_pull -> logging_rest, snmp -> snmp_observability). Guards the backend
    contract the cap-dialog advisory pane reads; a method missing the key would silently drop the prereq — the
    exact declare-path/credential-path divergence the audit flagged."""
    from kontroll import probe
    from kontroll.service import logsvc, observe
    facts = probe._facts("cisco.ios", "5.0.0", "local", "deep")
    facts["plugins"] = {"cliconf": ["ios"]}
    facts["modules"] = ["ios_command"]
    for offer in (logsvc.offerable_methods(facts), observe.offerable_methods(facts)):
        assert offer, "expected at least one offerable method"
        assert all("secret_domain" in m for m in offer), "every offerable method must expose secret_domain"
    log_dom = {m["name"]: m["secret_domain"] for m in logsvc.offerable_methods(facts)}
    assert log_dom.get("file_tail_ssh") == "logging_file_tail"
    assert log_dom.get("rest_pull") == "logging_rest"
    assert log_dom.get("syslog_push") is None        # a push method needs no SOPS cred -> no prereq surfaced
