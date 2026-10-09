"""add_capture_exception — adversarial-safe append into config/capture-exceptions.yml.

The matrix gates the backup pipeline (backup-configs.yml reads it), so a malformed entry is
an availability bug, not a cosmetic one. These tests prove the function NEVER corrupts the
file regardless of operator input — every value round-trips as a STRING (colons, YAML-special
words like `yes`, a line that looks like a `match:` field) — and that `match` is constrained to
a safe glob (it flows into a rendered .gitignore + `git rm` pathspecs downstream). Runs against
tmp_repo (kontroll.paths.ROOT repointed) so it never touches the real matrix.
"""
import pytest
import yaml

import galaxy

pytestmark = pytest.mark.unit


def _read(tmp_repo):
    return (tmp_repo / "config" / "capture-exceptions.yml").read_text(encoding="utf-8")


def _matches(tmp_repo):
    """The list of `match` values from the PARSED file (robust to quoting style)."""
    return [e["match"] for e in (yaml.safe_load(_read(tmp_repo)) or {}).get("exceptions", [])]


def test_add_appends_and_is_idempotent(tmp_repo):
    """A new match is appended once; re-adding the same match is a no-op (returns False, no dup)."""
    assert galaxy.add_capture_exception("acme", "Acme_*", "volatile",
                                        "exclude_from_history", "re-serializes", "user") is True
    assert "Acme_*" in _matches(tmp_repo)
    assert galaxy.add_capture_exception("acme", "Acme_*", "volatile",
                                        "exclude_from_history", "re-serializes", "user") is False
    assert _matches(tmp_repo).count("Acme_*") == 1


def test_add_preserves_header_and_seed_entry(tmp_repo):
    """The multi-line header comments and the seeded FortiGate entry survive an append intact."""
    galaxy.add_capture_exception("acme", "Acme_*", "volatile", "exclude_from_history", "x", "user")
    body = _read(tmp_repo)
    assert "# Capture-exception matrix" in body and "# Entry schema:" in body   # header survived
    assert "fortigate" in _read(tmp_repo)
    assert "FortiGate_*" in _matches(tmp_repo)                                   # seed entry intact


def test_appended_entry_is_valid_yaml_with_all_fields(tmp_repo):
    """The appended entry parses and carries every field with the supplied values."""
    galaxy.add_capture_exception("acme", "Acme_*", "volatile",
                                 "exclude_from_history", "observed text", "derived")
    e = next(x for x in yaml.safe_load(_read(tmp_repo))["exceptions"] if x["match"] == "Acme_*")
    assert e == {"subject": "acme", "match": "Acme_*", "behavior": "volatile",
                 "disposition": "exclude_from_history", "observed": "observed text", "source": "derived"}


# --- adversarial inputs: the file MUST stay valid YAML + values round-trip as strings -------- #
@pytest.mark.parametrize("subject", ["host:", "yes", "no", "123", "#weird", "{inline}", "a: b", "café"])
def test_yaml_special_subject_roundtrips_as_string(tmp_repo, subject):
    """A subject containing YAML-special text (colon, bool word, number, brace, unicode) must NOT
    corrupt the file or change type — it round-trips as the exact string. Guards the CRITICAL bug
    where unquoted scalars broke the whole matrix + every backup run."""
    galaxy.add_capture_exception(subject, "Adv_*", "volatile", "exclude_from_history", "obs", "user")
    doc = yaml.safe_load(_read(tmp_repo))                       # MUST still parse
    e = next(x for x in doc["exceptions"] if x["match"] == "Adv_*")
    assert e["subject"] == subject and isinstance(e["subject"], str)


def test_observed_with_colon_and_match_line_roundtrips_and_is_not_a_false_dup(tmp_repo):
    """An `observed` whose text contains colons and a line beginning `match:` must parse cleanly
    and NOT be mistaken for a real `match:` field (the old line-scan dup check's failure mode)."""
    obs = "saw this:\nmatch: not-a-field\nflaps: a lot"
    galaxy.add_capture_exception("dev", "Dev_*", "non_deterministic", "exclude_from_history", obs, "user")
    doc = yaml.safe_load(_read(tmp_repo))
    hits = [x for x in doc["exceptions"] if x["match"] == "Dev_*"]
    assert len(hits) == 1 and hits[0]["observed"] == obs       # exact round-trip, not a false dup


@pytest.mark.parametrize("bad", ['Foo"Bar_*', "Foo Bar_*", "#leading", "a/b", "back\\slash", "co:lon"])
def test_invalid_match_glob_is_rejected(tmp_repo, bad):
    """`match` is constrained to a filename glob — anything else (quote, space, '#', '/', '\\', ':')
    is rejected, because it would corrupt the rendered .gitignore or the `git rm` pathspec."""
    with pytest.raises(SystemExit):
        galaxy.add_capture_exception("dev", bad, "v", "exclude_from_history", "o", "user")


def test_missing_exceptions_key_exits(tmp_repo):
    """A matrix file with no `exceptions:` key is a hard error, not a silent malformed append."""
    (tmp_repo / "config" / "capture-exceptions.yml").write_text("other: {}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        galaxy.add_capture_exception("x", "X_*", "b", "exclude_from_history", "o", "user")


def test_corrupt_matrix_file_exits_rather_than_worsening_it(tmp_repo):
    """If the matrix is already invalid YAML, refuse to add (don't append onto a broken file)."""
    (tmp_repo / "config" / "capture-exceptions.yml").write_text("exceptions:\n  - a: b: c\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        galaxy.add_capture_exception("x", "X_*", "b", "exclude_from_history", "o", "user")
