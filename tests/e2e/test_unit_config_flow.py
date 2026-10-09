"""The app-store CONFIGURE flow, end-to-end in a headless browser over the REAL Flask app.

The seam's rendered UX: the Index panel grows a third **Automations** section (`GET /api/actuation`) listing the
registered units; a row's **Configure** opens `openUnitConfigDialog`, which mounts the curated-knob group (the
same `/api/configurable?kind=actuation-unit` projection + `renderKnobGroup`) and, on **Preview**, renders the
would-run play (`POST /api/actuation/<key>` `apply:false` — writing nothing). The hermetic contract (auth, the
preview/stage propose→stage split, the Tier-cap-free configure path, the audit) is covered in
`tests/integration/test_gui_api.py`; this proves the browser actually BUILDS the dialog + renders the knob form +
the preview. **Stage is NOT driven here** (it commits + needs an armed staging repo); the staged-result pane reuses
the already-proven `renderCapPromote`. One canned registered unit is mocked at `catalog.load_actuation_units`
(conftest), which flows through the registry view, the knob projection, AND the preview without overriding any
higher seam. Selectors are `data-testid` only (docs/testing-standards.md §3). opt-in via the `e2e` marker.
"""
import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_automations_configure_renders_knobs_and_previews(page):
    """Index → the Automations section → Configure opens the dialog, the curated knob renders (`knob-listen_port`
    via the shared `renderKnobGroup`), and Preview renders the would-run play (hosts = the derived inventory_group)
    — the Configure→Preview wiring proven in a real browser. expect() AUTO-WAITS each async fetch (the Automations
    list, the knob projection, the preview); a `.count()` snapshot would race the spinner. Guards the
    openUnitConfigDialog → /api/configurable → renderKnobGroup → /api/actuation preview path actually wiring up."""
    page.goto("/")
    page.get_by_test_id("fleet-open").click()
    # the Automations section fetch (/api/actuation) resolves async → auto-wait the registered-unit row.
    row = page.get_by_test_id("automation-row").first
    expect(row).to_be_visible(timeout=15000)
    expect(row).to_have_attribute("data-key", "community-docker-swarm")
    row.get_by_test_id("automation-configure").click()
    dlg = page.get_by_test_id("unit-config-dialog")
    expect(dlg).to_be_visible()
    expect(dlg).to_have_attribute("data-key", "community-docker-swarm")
    # the dialog opens synchronously with a spinner; the knob form lands after the /api/configurable fetch.
    expect(dlg.get_by_test_id("knob-listen_port")).to_be_visible(timeout=15000)
    dlg.get_by_test_id("unit-config-preview").click()
    # Preview POSTs apply:false; the would-run play lands after the fetch — auto-wait, then assert the derived group.
    play = dlg.get_by_test_id("unit-config-play")
    expect(play).to_be_visible(timeout=15000)
    expect(play).to_contain_text("docker_hosts")


def test_unit_config_dialog_closes(page):
    """The configure dialog's close control removes it — guards the modal lifecycle (an un-closable overlay would
    trap the operator on the page). Mirrors test_unit_dialog_closes."""
    page.goto("/")
    page.get_by_test_id("fleet-open").click()
    expect(page.get_by_test_id("automation-row").first).to_be_visible(timeout=15000)
    page.get_by_test_id("automation-configure").first.click()
    expect(page.get_by_test_id("unit-config-dialog")).to_be_visible()
    page.get_by_test_id("unit-config-close").click()
    expect(page.get_by_test_id("unit-config-dialog")).to_have_count(0)
