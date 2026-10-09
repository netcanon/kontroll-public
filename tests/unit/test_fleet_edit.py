"""enable_in_fleet — the comment-preserving, idempotent insert into instance/fleet.yml.

The fleet file is hand-curated (commented post-cutover entries the operator toggles),
so the editor must (1) insert after the last ACTIVE entry, above the commented ones,
(2) be a no-op if the key is already enabled, and (3) never drop the comments. Runs
against a throwaway repo (tmp_repo repoints kontroll.paths.ROOT) — never the real fleet file.
"""
import pytest

import galaxy

pytestmark = pytest.mark.unit


def _read_fleet(tmp_repo):
    """The tmp repo's instance/fleet.yml text."""
    return (tmp_repo / "config" / "fleet.yml").read_text(encoding="utf-8")


def test_enable_inserts_and_is_idempotent(tmp_repo):
    """Enabling a new module adds it once (returns True); enabling it again is a no-op (False,
    no duplicate) — guards against the onboard flow double-adding a class on re-run."""
    assert galaxy.enable_in_fleet("snmp_exporter") is True       # first time: changed
    body = _read_fleet(tmp_repo)
    assert "- snmp_exporter" in body

    assert galaxy.enable_in_fleet("snmp_exporter") is False      # second time: no-op
    assert _read_fleet(tmp_repo).count("- snmp_exporter") == 1   # not duplicated


def test_enable_preserves_commented_future_entries(tmp_repo):
    """The post-cutover commented-out entries the operator curates survive an enable untouched —
    a naive YAML load+dump would silently delete them."""
    galaxy.enable_in_fleet("snmp_exporter")
    body = _read_fleet(tmp_repo)
    # the post-cutover commented entries the operator curates must survive untouched
    assert "# - opnsense" in body
    assert "# - routeros" in body


# A fleet file in the shape the editor's placement rule is specified against: the active entries first, the
# operator's commented-out future entries after. Written EXPLICITLY (not the fleet tmp_repo copies — on a public
# checkout that is instance.example/fleet.yml, whose commented entries are interleaved as documentation), so the
# placement assertion below tests the editor, not whichever fleet file happens to be on disk.
_SHAPED_FLEET = """# fleet profile (test fixture)
enabled_modules:
  - proxmox
  - docker_host
  - cisco_ios
  # post-cutover entries the operator toggles later:
  # - opnsense
  # - routeros
"""


def test_new_entry_lands_among_active_not_after_comments(tmp_repo):
    """A new entry is inserted after the last ACTIVE module, above the commented-out ones — so it
    becomes active, not accidentally placed among (or after) the disabled future entries. Runs against an
    explicitly-shaped fleet text (active block, then the commented block) so the assertion is about the editor's
    placement rule, independent of the fleet file tmp_repo copied."""
    (tmp_repo / "config" / "fleet.yml").write_text(_SHAPED_FLEET, encoding="utf-8")
    galaxy.enable_in_fleet("snmp_exporter")
    lines = _read_fleet(tmp_repo).splitlines()
    active = [i for i, ln in enumerate(lines) if ln.strip().startswith("- ")]
    commented = [i for i, ln in enumerate(lines) if ln.strip().startswith("# - ")]
    new_at = next(i for i, ln in enumerate(lines) if "- snmp_exporter" in ln)
    # inserted after the last active entry, before the first commented-out one
    assert new_at == max(active)
    assert new_at < min(commented)


def test_already_enabled_existing_key_is_noop(tmp_repo):
    """Enabling a key already present in the seed fleet is a no-op (False) — idempotent against
    the real starting state, not just an empty file."""
    assert galaxy.enable_in_fleet("cisco_ios") is False          # already in the seed fleet


def test_missing_enabled_modules_key_raises(tmp_repo):
    """A fleet file with no `enabled_modules:` key is a hard error, not a silent malformed write — and it RAISES
    (a catchable ValueError), never `sys.exit` (S-3/G9 fix, Phase 5): a SystemExit would kill the in-process
    GUI/API worker mid-request; the CLI catches the raise at dispatch."""
    (tmp_repo / "config" / "fleet.yml").write_text("other: {}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        galaxy.enable_in_fleet("whatever")
