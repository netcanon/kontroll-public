"""The graceful-export probe (S6) — suggest_logging's optional `evidence` enrichment + probe.logging_export_probe.

Guards against the probe ever becoming a GATE (the load-bearing INVARIANT-D property). The probe is a read-only,
fail-soft, NON-GATING nudge: with the probe absent suggest_logging behaves byte-identically to before, and when
present it can only SHARPEN the note of a candidate the vector+hint ALREADY produced — never add, remove, or
gate a candidate. Also pins that logging_export_probe is fail-soft (a probe failure degrades to 'maybe', never
raises) and that the capabilities/logging.yml `probe:` descriptor field binds to a real callable (config-as-data,
not drift). A regression to a gating probe or a raising helper would reopen the INVARIANT-D / fail-soft hole.
"""
import pytest

from kontroll import probe
from kontroll.service.classify import suggest_logging
from kontroll import catalog

pytestmark = pytest.mark.unit

_CLICONF = {"cliconf": ["ios"]}        # a network_cli device -> the vector+hint derive a syslog_push candidate
_HTTPAPI = {"httpapi": ["x"]}          # no log-export-shaped signal -> NO candidate (nothing to sharpen)


# --- suggest_logging evidence contract (INVARIANT-D) ------------------------------------------------------- #
def test_evidence_none_is_byte_identical_to_today(vectors, make_facts):
    """evidence=None (the default and the ONLY path onboarding takes) returns EXACTLY {cell, candidates, note}
    with no `evidence` key, identical to calling without the arg — the INVARIANT-D regression pin proving the
    probe plumbing left the onboard/spine behaviour untouched."""
    facts = make_facts(plugins=_CLICONF)
    bare = suggest_logging(facts, vectors)
    explicit_none = suggest_logging(facts, vectors, evidence=None)
    assert set(explicit_none) == {"cell", "candidates", "note"}
    assert "evidence" not in explicit_none
    assert explicit_none == bare


def test_evidence_yes_sharpens_note_but_never_changes_candidates(vectors, make_facts):
    """A probe state 'yes' re-words the note (surfaces the probe evidence) and echoes the evidence, but the
    candidate list is IDENTICAL to the evidence-less call — the probe SHARPENS, it never adds/removes a
    candidate. Guards a probe that silently widens the suggestion."""
    facts = make_facts(plugins=_CLICONF)
    bare = suggest_logging(facts, vectors)
    sharp = suggest_logging(facts, vectors, evidence={"state": "yes", "note": "x"})
    assert sharp["candidates"] == bare["candidates"]          # NEVER changed
    assert sharp["note"] != bare["note"] and "probe" in sharp["note"]
    assert sharp["evidence"] == {"state": "yes", "note": "x"}


def test_evidence_no_keeps_the_candidate_offerable(vectors, make_facts):
    """A probe state 'no' (no syslog-host line seen) does NOT remove the candidate — the static signal still
    makes the method offerable; the note is merely annotated. Guards a probe that downgrades a real candidate
    to nothing (that would make it a de-facto gate)."""
    facts = make_facts(plugins=_CLICONF)
    sharp = suggest_logging(facts, vectors, evidence={"state": "no", "note": "x"})
    assert "syslog_push" in sharp["candidates"]               # STILL offerable
    assert "still offerable" in sharp["note"]


def test_evidence_cannot_manufacture_a_candidate(vectors, make_facts):
    """With NO log-export signal (httpapi only) the candidate list is empty — and even a 'yes' probe cannot
    add one or leak an `evidence` key. The probe can only sharpen a candidate the vector+hint ALREADY produced,
    so it can never become the thing that turns a non-candidate into one. The strongest non-gating pin."""
    facts = make_facts(modules=["thing"], plugins=_HTTPAPI)
    sharp = suggest_logging(facts, vectors, evidence={"state": "yes", "note": "x"})
    assert sharp["candidates"] == []
    assert "evidence" not in sharp                            # nothing sharpened -> the 3-key contract holds


# --- logging_export_probe fail-soft contract -------------------------------------------------------------- #
def test_probe_is_fail_soft_when_the_read_raises():
    """A run_show that raises (unreachable / timeout / unknown command) degrades to {state: 'maybe'} and NEVER
    propagates — a probe failure must never be able to abort an operator action (INVARIANT-D / fail-soft)."""
    def boom(addr, conn):
        raise RuntimeError("device unreachable")
    res = probe.logging_export_probe("192.0.2.9", object(), boom)
    assert res["state"] == "maybe"


def test_probe_detects_a_configured_syslog_host():
    """A read whose output contains a syslog-host marker -> state 'yes'. Guards the detection going blind to a
    real `logging host` line (the evidence that sharpens the suggestion)."""
    res = probe.logging_export_probe("192.0.2.9", None, lambda a, c: "logging host 203.0.113.10\n")
    assert res["state"] == "yes"


def test_probe_reports_no_when_no_syslog_host_line():
    """A read with no syslog-host marker -> state 'no' (still offerable). Guards a false-positive 'yes' that
    would over-sharpen a device that does not actually export logs."""
    res = probe.logging_export_probe("192.0.2.9", None, lambda a, c: "Current configuration : 1450 bytes\n")
    assert res["state"] == "no"


# --- descriptor binding (config-as-data, not drift) ------------------------------------------------------- #
def test_descriptor_probe_binds_to_a_real_fail_soft_callable():
    """capabilities/logging.yml's `probe:` field names a module/fn that resolves to a REAL callable
    (kontroll.probe.logging_export_probe) — so the config-as-data read spec can't drift from the code (a
    renamed helper becomes a test failure, mirroring the _LOGGING_HINT drift pin)."""
    d = next(c for c in catalog.load_capabilities() if c["name"] == "logging")
    assert d["probe"]["module"] == "probe"
    fn = getattr(probe, d["probe"]["fn"])
    assert callable(fn)
