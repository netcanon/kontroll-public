"""The telemetry capability vector (vectors/telemetry.yml) — the DETECTED side of observability.

These pin that the 4th vector loads + sorts last, resolves the three states from the right collection
signals (httpapi -> yes/medium, cliconf -> yes/low, raw-ssh -> no), and is DEPTH-STABLE: it uses only
plugin/module_suffix/any_of(plugin) rules (visible at both shallow and deep), so it never produces a
'maybe' on its own (the parity-safety property). They guard the vector from silently never matching, and
from being upgraded to a 'maybe'-producing (module_option) rule without the matching parity test.
"""
import pytest

from kontroll import predicate

pytestmark = pytest.mark.unit


def _telem(vectors):
    return next(v for v in vectors if v["name"] == "telemetry")


def test_telemetry_vector_loads_and_sorts_after_the_original_cells(vectors):
    """vectors/telemetry.yml is discovered by load_vectors and sorts right after actuate/backup/bespoke
    (order 4) — guards the drop-in not being picked up, or reordering the original cells (which the CLI/GUI
    render positionally). It is no longer the ABSOLUTE last cell: the logging vector (order 5) appends after
    it; this asserts telemetry's position relative to the original three, not that it is last."""
    names = [v["name"] for v in vectors]
    assert "telemetry" in names
    assert names.index("telemetry") == names.index("bespoke") + 1   # immediately after the original three


def test_telemetry_yes_medium_from_httpapi(vectors, make_facts):
    """An httpapi (REST) collection yields telemetry=yes at MEDIUM confidence — the proxy-exporter-shaped
    signal (an API exporter could scrape it). Guards the vector silently never matching its primary rule."""
    res = predicate.eval_vector(_telem(vectors), make_facts(plugins={"httpapi": ["fortios"]}))
    assert res["state"] == "yes" and res["confidence"] == "medium"
    assert res["evidence"].startswith("httpapi")


def test_telemetry_yes_low_from_cliconf(vectors, make_facts):
    """A network_cli (cliconf) device yields telemetry=yes at LOW confidence — the agent-less snmp/blackbox
    candidate. Guards the confidence ordering: scrapability via cliconf is a WEAKER claim than backup's
    high-confidence cliconf rule, so telemetry must read low here, never high."""
    res = predicate.eval_vector(_telem(vectors), make_facts(plugins={"cliconf": ["ios"]}))
    assert res["state"] == "yes" and res["confidence"] == "low"


def test_telemetry_no_for_raw_ssh_appliance(vectors, make_facts):
    """A raw-SSH appliance (no plugins, no _facts module) yields telemetry=no — the honest 'no scrape-shaped
    signal' case. Guards a false-positive scrapable label on a device exposing nothing collection-visible."""
    res = predicate.eval_vector(_telem(vectors), make_facts(modules=["thing"], plugins={}))
    assert res["state"] == "no"


def test_telemetry_is_depth_stable_never_maybe(vectors, make_facts):
    """telemetry uses only plugin/module_suffix/any_of(plugin) rules — all visible at BOTH shallow and deep
    — so it never reads 'maybe'. The parity-safety property: a future maintainer adding a module_option
    (deep-only) rule introduces a 'maybe' path and must add the matching parity test; this flips red if
    telemetry ever returns 'maybe' for an all-shallow fact set."""
    res = predicate.eval_vector(_telem(vectors), make_facts(plugins={"cliconf": ["ios"]}, module_options={}))
    assert res["state"] != "maybe"
