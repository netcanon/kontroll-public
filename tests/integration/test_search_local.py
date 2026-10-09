"""search as a black box — local + galaxy sources mocked, --json output asserted.

Drives cmd_search with the I/O seams (local_shallow, deep_probe, galaxy_search) patched, so the full
source->record->filter->render pipeline runs offline. Local hits are SHALLOW by default (the redesign);
the --vector capability filter forces the DEEP probe, so deep_probe is stubbed too. Covers the "show me
only things that can back up" path.
"""
import json
import types

import pytest

import galaxy
from kontroll import catalog, probe

pytestmark = pytest.mark.integration


def _args(**over):
    base = dict(keywords=["cisco"], origin="both", limit=8, vector=[], deep=False, json=True)
    base.update(over)
    return types.SimpleNamespace(**base)


@pytest.fixture
def mock_sources(monkeypatch, make_facts):
    """Patch the I/O seams so search runs offline: a keyword-aware local_shallow yielding one cliconf
    collection (cisco.ios) as SHALLOW facts, deep_probe returning cliconf facts (for the vector/deep
    paths), and an empty Galaxy result. local_shallow honours the keyword so the miss test returns []."""
    def fake_shallow(kw, limit):
        if any("cisco" in k.lower() for k in kw):
            return [make_facts(collection="cisco.ios", version="5.0.0", depth="shallow",
                               plugins={"cliconf": ["ios"]}, modules=["ios_command"])]
        return []
    monkeypatch.setattr(catalog, "local_shallow", fake_shallow)
    monkeypatch.setattr(probe, "deep_probe",
                        lambda coll, version=None: make_facts(
                            collection=coll, version=version or "5.0.0",
                            plugins={"cliconf": ["ios"]}, modules=["ios_command"]))
    monkeypatch.setattr(catalog, "galaxy_search", lambda kw, limit: [])


def _records(capsys):
    return json.loads(capsys.readouterr().out)


def test_local_hit_becomes_a_classified_record(tmp_repo, mock_sources, capsys):
    """A local keyword hit becomes a classified record (origin=local, depth=shallow, suggested backend,
    backup=yes) — the fast SHALLOW path that turns an installed collection into a result. backup is 'yes'
    even shallow because a cliconf plugin confers it (a file-visible signal), not the deep-only option."""
    galaxy.cmd_search(_args())
    recs = _records(capsys)
    assert len(recs) == 1
    assert recs[0]["collection"] == "cisco.ios"
    assert recs[0]["origin"] == "local" and recs[0]["depth"] == "shallow"
    assert recs[0]["suggested_backend"] == "netcommon_cli"
    assert recs[0]["capabilities"]["backup"]["state"] == "yes"


def test_vector_filter_keeps_matching_capability(tmp_repo, mock_sources, capsys):
    """`--vector backup` keeps a result that HAS the backup capability (a cliconf device)."""
    galaxy.cmd_search(_args(vector=["backup"]))      # cliconf confers backup
    assert len(_records(capsys)) == 1


def test_vector_filter_drops_nonmatching_capability(tmp_repo, mock_sources, capsys):
    """`--vector bespoke` drops a result that LACKS it — the cliconf device is not bespoke."""
    galaxy.cmd_search(_args(vector=["bespoke"]))     # a cliconf device is NOT bespoke
    assert _records(capsys) == []


def test_keyword_miss_returns_nothing(tmp_repo, mock_sources, capsys):
    """A keyword that matches no installed collection (and no Galaxy hit) returns an empty list."""
    galaxy.cmd_search(_args(keywords=["nonexistent"]))
    assert _records(capsys) == []
