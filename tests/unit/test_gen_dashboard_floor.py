"""scripts/gen-dashboard-floor.py — the dashboard-floor DERIVE engine (north-star Rung 4a).

Even the grafana.com board *id* is DERIVED from the parseable registry (a `derive_dashboard:` search selector on
telemetry/<method>.yml), deterministically ranked, and PINNED to dashboards/derived/<method>.lock.yml so an OFFLINE
`--check` validates it (BRICK-1: no network in an install-gating path). These tests pin the security-critical
behaviours: the ranked pick is deterministic (so the pin never churns silently), the honesty guards (datasource +
series fit) reject a board the method's series can't feed, `--check` is genuinely offline, the sha256 floor catches
a tampered board, and a board swap is LOUD. The script is hyphenated, so it is loaded by path (not importable).
"""
import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytestmark = pytest.mark.unit


def _gdf():
    spec = importlib.util.spec_from_file_location(
        "gen_dashboard_floor", os.path.join(ROOT, "scripts", "gen-dashboard-floor.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gdf = _gdf()


def _item(gid, downloads, slugs=("prometheus",)):
    return {"id": gid, "downloads": downloads, "datasourceSlugs": list(slugs)}


def _mock_fetch(boards):
    """A fd.fetch(gnet) stand-in returning (rev, name, dash) from a {gnet: dash} map — the network board download."""
    def fetch(gnet):
        return 1, "board-%d" % gnet, boards[gnet]
    return fetch


# --- the DETERMINISTIC ranked pick ---------------------------------------------------------------------------

def test_resolve_prefers_the_soft_gnet_when_present(monkeypatch):
    """A prefer_gnet id that is PRESENT in the live results wins over a higher-download board — the soft pin lets a
    descriptor bless the canonical board without typing a bare id. Guards a downloads-ranked #1 (e.g. an unrelated
    board that merely matches the query text) silently displacing the intended floor board."""
    monkeypatch.setattr(gdf, "_search", lambda q, ds: [_item(2, 9999), _item(1860, 5)])
    monkeypatch.setattr(gdf.fd, "fetch", _mock_fetch({2: {"e": "x"}, 1860: {"e": "node_cpu_seconds_total"}}))
    sel = {"search": "node", "datasource": "prometheus", "requires_series": "node_cpu_seconds_total",
           "prefer_gnet": [1860], "name": "node"}
    rec = gdf.resolve_method("host_node", sel)
    assert rec["id"] == 1860 and rec["chosen_by"] == "prefer_gnet"


def test_resolve_falls_to_downloads_then_id_ascending(monkeypatch):
    """With no prefer_gnet, the pick is the most-downloaded candidate; a downloads TIE breaks to the LOWEST id
    (older/more-established, a total integer order — never a timestamp/float). Guards non-deterministic ranking:
    two operators resolving the same registry snapshot must pin the same board."""
    monkeypatch.setattr(gdf, "_search", lambda q, ds: [_item(5, 50), _item(2, 50), _item(9, 10)])
    monkeypatch.setattr(gdf.fd, "fetch", _mock_fetch({5: {"e": "probe_success"}, 2: {"e": "probe_success"},
                                                      9: {"e": "probe_success"}}))
    sel = {"search": "blackbox", "datasource": "prometheus", "requires_series": "probe_success", "name": "blackbox"}
    rec = gdf.resolve_method("blackbox", sel)
    assert rec["id"] == 2 and rec["chosen_by"] == "downloads"   # 50==50 tie -> lowest id (2), not 5


# --- the HONESTY guards (datasource + series fit) ------------------------------------------------------------

def test_resolve_hard_filters_the_wrong_datasource(monkeypatch):
    """A candidate whose datasourceSlugs lack the selector's datasource is DISQUALIFIED (not merely ranked below):
    a Graphite board can't ride our Prometheus method. Guards attaching a board that cannot query our datasource."""
    monkeypatch.setattr(gdf, "_search", lambda q, ds: [_item(7, 9999, slugs=["graphite"]), _item(3, 4)])
    monkeypatch.setattr(gdf.fd, "fetch", _mock_fetch({3: {"e": "ifHCInOctets"}}))
    sel = {"search": "snmp", "datasource": "prometheus", "requires_series": "ifHCInOctets", "name": "snmp_if"}
    rec = gdf.resolve_method("snmp", sel)
    assert rec["id"] == 3   # the graphite board (7) was filtered out despite far more downloads


def test_resolve_skips_a_board_missing_the_required_series(monkeypatch):
    """The top-ranked candidate whose pinned JSON does NOT contain requires_series is skipped; the pick falls through
    to the first candidate that DOES query the series. Guards a 'node exporter'-named board that actually queries a
    different exporter (the series-fit honesty guard) — the never-fake contract for boards."""
    monkeypatch.setattr(gdf, "_search", lambda q, ds: [_item(1, 100), _item(2, 50)])
    monkeypatch.setattr(gdf.fd, "fetch", _mock_fetch({1: {"e": "unrelated_metric"}, 2: {"e": "node_cpu_seconds_total"}}))
    sel = {"search": "node", "datasource": "prometheus", "requires_series": "node_cpu_seconds_total", "name": "node"}
    rec = gdf.resolve_method("host_node", sel)
    assert rec["id"] == 2   # 1 had more downloads but lacked the series -> fell through


def test_resolve_raises_when_no_candidate_fits(monkeypatch):
    """If NO candidate satisfies the series fit, resolve_method raises (fail-honest: it never emits a board it can't
    justify). Guards fabricating a floor board from a selector alone."""
    monkeypatch.setattr(gdf, "_search", lambda q, ds: [_item(1, 100)])
    monkeypatch.setattr(gdf.fd, "fetch", _mock_fetch({1: {"e": "nope"}}))
    with pytest.raises(LookupError):
        gdf.resolve_method("host_node", {"search": "x", "datasource": "prometheus",
                                         "requires_series": "node_cpu_seconds_total", "name": "node"})


# --- the OFFLINE --check (BRICK-1 + sha256 floor + selector coherence) ---------------------------------------

def test_check_is_offline(monkeypatch):
    """`--check` over the committed pins makes NO grafana.com call: monkeypatch the network seams (_search + fd.fetch)
    to RAISE, and check() still returns clean. Guards a network call sneaking into the install-gating path (BRICK-1),
    the never-brick invariant — an air-gapped / registry-down validate must never fail on the dashboard floor."""
    def boom(*a, **k):
        raise AssertionError("check() must not touch the network")
    monkeypatch.setattr(gdf, "_search", boom)
    monkeypatch.setattr(gdf.fd, "fetch", boom)
    assert gdf.check() == []


def test_committed_floor_locks_are_coherent():
    """The REAL committed dashboards/derived/*.lock.yml + their boards + the telemetry selectors are coherent — the
    end-to-end frozen pin. Guards a hand-edited lock/board or a stale selector landing without a re-resolve."""
    assert gdf.check() == []


def test_check_catches_a_tampered_board(tmp_path, monkeypatch):
    """A committed board whose bytes no longer hash to the lock's content_sha256 fails --check, naming the method —
    the OFFLINE tamper floor (the dashboard analogue of L2b's recorded-sha256). Guards a hand-edited/bytes-drifted
    board silently diverging from the reviewed pin."""
    monkeypatch.setattr(gdf, "BOARDS_DIR", str(tmp_path))
    board = {"title": "t", "expr": "node_cpu_seconds_total"}
    (tmp_path / "node.json").write_bytes(gdf._board_bytes(board))
    lock = {"schema": 1, "method": "host_node", "name": "node", "id": 1860, "revision": 45,
            "datasource": "prometheus", "content_sha256": gdf._sha256_bytes(gdf._board_bytes(board)),
            "requires_series": "node_cpu_seconds_total"}
    sel = {"datasource": "prometheus", "requires_series": "node_cpu_seconds_total"}
    assert gdf._check_lock("host_node", lock, sel) == []                      # coherent
    (tmp_path / "node.json").write_bytes(gdf._board_bytes({"title": "MUTATED", "expr": "node_cpu_seconds_total"}))
    problems = gdf._check_lock("host_node", lock, sel)
    assert any("sha256" in p for p in problems)                              # tamper caught


def test_check_flags_selector_lock_drift(tmp_path, monkeypatch):
    """A lock whose datasource/requires_series no longer match its telemetry selector fails --check (an operator edited
    the descriptor without re-resolving). Guards the descriptor and its pin silently diverging."""
    monkeypatch.setattr(gdf, "BOARDS_DIR", str(tmp_path))
    board = {"expr": "ifHCInOctets"}
    (tmp_path / "snmp_if.json").write_bytes(gdf._board_bytes(board))
    lock = {"schema": 1, "method": "snmp", "name": "snmp_if", "id": 1124, "revision": 4,
            "datasource": "prometheus", "content_sha256": gdf._sha256_bytes(gdf._board_bytes(board)),
            "requires_series": "ifHCInOctets"}
    drifted = {"datasource": "loki", "requires_series": "ifHCInOctets"}      # selector says loki now
    assert any("datasource" in p for p in gdf._check_lock("snmp", lock, drifted))


def test_check_flags_an_orphan_lock(tmp_path, monkeypatch):
    """A lock with NO matching telemetry derive_dashboard: selector is flagged (sel=None) — a dangling pin for a
    method that no longer derives a board. Guards a removed selector leaving a stale board provisioned."""
    monkeypatch.setattr(gdf, "BOARDS_DIR", str(tmp_path))
    board = {"expr": "probe_success"}
    (tmp_path / "blackbox.json").write_bytes(gdf._board_bytes(board))
    lock = {"schema": 1, "method": "blackbox", "name": "blackbox", "id": 13659, "revision": 1,
            "datasource": "prometheus", "content_sha256": gdf._sha256_bytes(gdf._board_bytes(board)),
            "requires_series": "probe_success"}
    assert any("orphan" in p for p in gdf._check_lock("blackbox", lock, None))


# --- MF-5 loud-on-swap ---------------------------------------------------------------------------------------

def test_resolve_warns_loudly_on_a_board_swap(tmp_path, monkeypatch, capsys):
    """When --resolve pins a DIFFERENT gnet than the existing lock, it prints a LOUD stderr warning naming the swap
    (the reviewable git diff is the safety; the warning makes a board-swap non-silent). Guards the search tier
    silently churning the pinned board on the operator's behalf."""
    monkeypatch.setattr(gdf, "LOCKS_DIR", str(tmp_path))
    monkeypatch.setattr(gdf, "BOARDS_DIR", str(tmp_path))
    monkeypatch.setattr(gdf, "_selectors", lambda: [("host_node", {
        "search": "node", "datasource": "prometheus", "requires_series": "node_cpu_seconds_total",
        "prefer_gnet": [1860], "name": "node"})])
    monkeypatch.setattr(gdf, "_search",
                        lambda q, ds: [{"id": 1860, "downloads": 10, "datasourceSlugs": ["prometheus"]}])
    monkeypatch.setattr(gdf.fd, "fetch", _mock_fetch({1860: {"e": "node_cpu_seconds_total"}}))
    (tmp_path / "host_node.lock.yml").write_text(
        "schema: 1\nmethod: host_node\nname: node\nid: 999\nrevision: 1\n"
        "datasource: prometheus\ncontent_sha256: \"x\"\nrequires_series: node_cpu_seconds_total\n", encoding="utf-8")
    assert gdf.resolve() == 0
    assert "SWAPPED gnet 999 -> 1860" in capsys.readouterr().err


def test_resolve_rejects_an_unknown_method(monkeypatch, capsys):
    """`--resolve <typo>` fails LOUDLY (returns 1 + names the valid methods) instead of silently resolving nothing.
    Guards an operator typo on the network path being mistaken for a successful re-pin."""
    monkeypatch.setattr(gdf, "_selectors", lambda: [("host_node", {
        "search": "x", "datasource": "prometheus", "requires_series": "y", "name": "node"})])
    assert gdf.resolve(only="hostnode") == 1               # typo'd method name
    assert "no telemetry method" in capsys.readouterr().err


# --- MF-1 BRICK-1 static gate (the Windows-safe pytest twin of the validate.sh step) -------------------------

def test_resolve_is_absent_from_the_install_gating_path():
    """No install-gating path (ansible/playbooks/deploy-stack.yml or any .github/workflows/*.yml) invokes
    gen-dashboard-floor.py --resolve — the network DERIVE leg is operator/control-VM only; deploy + CI run the
    OFFLINE --check. The pytest twin of the validate.sh static gate (validate.ps1/Windows runs no shell steps).
    Guards a grafana.com network call sneaking into an install path (BRICK-1). Whitespace/newline-robust (unlike the
    line-oriented validate.sh twin) so a shell line-continuation split (`gen-dashboard-floor.py \\<newline>--resolve`)
    can't evade it — collapse continuations + whitespace, then match within a bounded gap."""
    import glob
    import re
    pat = re.compile(r"gen-dashboard-floor\.py.{0,80}?--resolve|--resolve.{0,80}?gen-dashboard-floor\.py")
    files = [os.path.join(ROOT, "ansible", "playbooks", "deploy-stack.yml")]
    files += glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))

    def _norm(text):   # fold `\<newline>` line-continuations + all whitespace to single spaces
        return re.sub(r"\s+", " ", text.replace("\\\n", " "))
    offenders = [f for f in files if os.path.exists(f) and pat.search(_norm(open(f, encoding="utf-8").read()))]
    assert offenders == [], "install-gating path invokes --resolve: %s" % offenders
