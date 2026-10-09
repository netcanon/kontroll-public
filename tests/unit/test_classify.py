"""classify(facts, backends) — the single dispatch seam's auto-matcher.

Pins each backend's structural signature against synthetic facts, and that the
`manual` backend (napalm) is NEVER auto-matched. Asserts membership + the
lowest-`order` winner (suggested backend), not full-list equality, so adding a new
backend doesn't break these. Mirrors the real ansible/backends/*/backend.yml rules.
"""
import pytest

import galaxy

pytestmark = pytest.mark.unit


def _suggested(facts, backends):
    """The first (lowest-order) backend classify() matches, or None — the 'suggested' backend."""
    matches = galaxy.classify(facts, backends)
    return matches[0] if matches else None


def test_cliconf_maps_to_netcommon_cli(backends, make_facts):
    """A cliconf plugin auto-classifies to netcommon_cli, and it wins as the suggested backend
    (order 1) — the common network_cli device path."""
    f = make_facts(plugins={"cliconf": ["ios"]}, modules=["ios_command"])
    matches = galaxy.classify(f, backends)
    assert "netcommon_cli" in matches
    assert _suggested(f, backends) == "netcommon_cli"   # order 1 — the winner


def test_httpapi_only_maps_to_api(backends, make_facts):
    """An httpapi-only collection (no cliconf) auto-classifies to the api backend, not cli."""
    f = make_facts(plugins={"httpapi": ["fortios"]})
    matches = galaxy.classify(f, backends)
    assert "netcommon_cli" not in matches
    assert _suggested(f, backends) == "api"


def test_bespoke_maps_to_raw_ssh(backends, make_facts):
    """A collection with no usable plugin/_config signal (the negative space) falls to raw_ssh,
    never to the structured cli/api backends."""
    f = make_facts(modules=["weird_thing"])             # no plugins, no _config
    matches = galaxy.classify(f, backends)
    assert "raw_ssh" in matches
    assert "api" not in matches and "netcommon_cli" not in matches


def test_config_module_with_backup_option_maps_to_vendor_config(backends, make_facts):
    """A vendor *_config module that exposes a `backup:` option auto-classifies to vendor_config —
    and is NOT treated as bespoke (a _config module is structured, not raw)."""
    f = make_facts(modules=["ios_config"], module_options={"ios_config": ["backup", "lines"]})
    matches = galaxy.classify(f, backends)
    assert "vendor_config" in matches
    assert "raw_ssh" not in matches                     # a _config module is not bespoke


def test_manual_backend_never_autoclassified(backends, make_facts):
    """napalm is select-by-driver; no structural facts should ever auto-pick it."""
    for f in (make_facts(plugins={"cliconf": ["ios"]}),
              make_facts(plugins={"httpapi": ["x"]}),
              make_facts(modules=["thing"])):
        assert "napalm" not in galaxy.classify(f, backends)
