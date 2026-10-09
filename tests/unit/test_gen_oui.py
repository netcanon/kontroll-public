"""gen-oui.py --check coherence gate (the pinned IEEE OUI->vendor lookup, discovery display-hint Rung 3).

WHY these tests (the failures they guard): the pinned OUI lookup is a ~2 MB GENERATED artifact read at runtime for a
display hint, and the OFFLINE `--check` gate is what keeps it honest in tests/validate — a tamper, a stale count, a
bad key, or a source change must fail loudly, and the network DERIVE (`--refresh`) must NEVER run in an install-gating
path (BRICK-1). Each test pins one leg: a coherent lock passes; a sha/count/key-shape defect fails (the tamper +
honest-count + key-shape floors); `--check` makes no network call even with urlopen booby-trapped. Mirrors the
gen-dashboard-floor / gen-image-digests offline-gate discipline.
"""
import importlib.util
import os

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load():
    """Load the hyphenated top-level generator as a module (the repo's standard test seam)."""
    spec = importlib.util.spec_from_file_location("gen_oui", os.path.join(ROOT, "scripts", "gen-oui.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen_oui = _load()


def _write_pin(d, prefixes):
    """Write a byte-coherent tiny lookup + matching lock into dir `d` (via the REAL _lookup_bytes/render_lock so the
    sha + count agree), and return the two paths."""
    data = gen_oui._lookup_bytes(prefixes)
    sha = gen_oui._sha256_bytes(data)
    lj = os.path.join(str(d), "oui-lookup.generated.json")
    ll = os.path.join(str(d), "oui-lookup.lock.yml")
    with open(lj, "wb") as fh:
        fh.write(data)
    with open(ll, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(gen_oui.render_lock(prefixes, sha, "2026-07-04"))
    return lj, ll


def _point(monkeypatch, d):
    monkeypatch.setattr(gen_oui, "LOOKUP", os.path.join(str(d), "oui-lookup.generated.json"))
    monkeypatch.setattr(gen_oui, "LOCK", os.path.join(str(d), "oui-lookup.lock.yml"))


def test_check_passes_on_coherent_lock(tmp_path, monkeypatch):
    """A hand-built tiny lookup + matching lock passes --check (schema, 6/7/9-hex keys, count, sha256, the exact 3
    IEEE sources). Guards the offline coherence gate accepting a good artifact."""
    _write_pin(tmp_path, {"00005e": "IANA", "00005e0": "IANA-M", "00005e005": "IANA-S"})
    _point(monkeypatch, tmp_path)
    assert gen_oui.check() == []


def test_check_fails_on_sha_mismatch(tmp_path, monkeypatch):
    """Tampering the .json after the lock is written makes sha256(json) != lock.content_sha256 -> --check fails (the
    tamper floor). Guards the pinned lookup drifting from its lock unnoticed (a swapped vendor / injected value)."""
    lj, _ = _write_pin(tmp_path, {"00005e": "IANA"})
    _point(monkeypatch, tmp_path)
    with open(lj, "rb") as fh:
        raw = fh.read()
    with open(lj, "wb") as fh:
        fh.write(raw.replace(b"IANA", b"EVIL"))          # same length -> count still ok, only the sha differs
    assert any("content_sha256" in p for p in gen_oui.check())


def test_check_fails_on_count_mismatch(tmp_path, monkeypatch):
    """A lock whose prefix_count != the actual key count fails --check (the honest-count invariant — a number kept
    honest by a check, not prose, per CLAUDE.md). Guards a lock/artifact count divergence."""
    _, ll = _write_pin(tmp_path, {"00005e": "IANA", "00005e0": "IANA-M"})
    _point(monkeypatch, tmp_path)
    with open(ll, encoding="utf-8") as fh:
        lock = fh.read()
    with open(ll, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(lock.replace("prefix_count: 2", "prefix_count: 99"))
    assert any("prefix_count" in p for p in gen_oui.check())


def test_check_fails_on_bad_key_length(tmp_path, monkeypatch):
    """A key that is not 6/7/9 lowercase-hex nibbles (here an 8-nibble key) fails --check. Guards a malformed prefix
    that would silently never match — the longest-prefix reader probes exactly 9/7/6 nibbles."""
    _write_pin(tmp_path, {"00005e": "IANA", "deadbeef": "eight-nibble-invalid"})   # 8 nibbles -> not 6/7/9
    _point(monkeypatch, tmp_path)
    assert any("6/7/9" in p for p in gen_oui.check())


def test_check_fails_when_lookup_missing(tmp_path, monkeypatch):
    """A missing oui-lookup.generated.json fails --check with a 're-run --refresh' hint (never a silent pass, never a
    fetch). Guards the fail-closed default + the BRICK-1 no-implicit-refresh posture."""
    _point(monkeypatch, tmp_path)                        # empty dir — no artifact written
    problems = gen_oui.check()
    assert problems and "missing" in problems[0]


def test_check_makes_no_network_call(tmp_path, monkeypatch):
    """BRICK-1: --check is OFFLINE — it passes on a good artifact even with urllib.request.urlopen booby-trapped to
    raise. Guards a network call sneaking into the install-gating path (validate + deploy run only --check, never
    --refresh). The static twin is the validate.sh `oui-refresh-not-in-deploy` grep-gate."""
    _write_pin(tmp_path, {"00005e": "IANA"})
    _point(monkeypatch, tmp_path)

    def _boom(*a, **k):
        raise AssertionError("network call in the --check path (BRICK-1 violation)")

    monkeypatch.setattr(gen_oui.urllib.request, "urlopen", _boom)
    assert gen_oui.check() == []
