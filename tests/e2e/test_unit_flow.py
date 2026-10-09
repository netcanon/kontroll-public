"""The app-store create-unit dialog, end-to-end in a headless browser over the REAL Flask app.

The seam's rendered UX (report 24 §2): the ⚙ Automations badge on a result card opens `openUnitDialog`, which lists
the collection's runnable units (or an honest-empty/degraded pane), and picking → Review proposes the create plan
WITHOUT writing. The hermetic API contract (auth, propose purity, the Tier-cap 403, the token-gated create + audit,
the proposed-ref staging) is covered in `tests/integration/test_gui_api.py`; this proves the browser actually builds
the dialog. Create/stage is NOT driven here (it commits + needs an armed staging repo); the staged-result rendering
reuses the proven `renderCapPromote` (exercised via `page.evaluate`). Selectors are `data-testid` only
(docs/testing-standards.md §3). opt-in via the `e2e` marker.
"""
import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_unit_badge_opens_dialog_and_renders_unit_body(page):
    """Searching → clicking the ⚙ Automations badge opens the unit dialog for the collection and renders the
    unit-body (the runnable-unit list, or the honest empty/degraded pane for a modules-only / uninstalled
    collection) — the Search→Pick wiring proven in a real browser. Guards the openUnitDialog → GET /api/units →
    render path actually wiring up (the create-dialog acceptance: the badge opens the modal)."""
    page.goto("/")
    page.get_by_test_id("search-input").fill("cisco ios")
    page.get_by_test_id("search-btn").click()
    card = page.get_by_test_id("card").first
    expect(card).to_be_visible()
    card.get_by_test_id("unit-badge").click()
    dlg = page.get_by_test_id("unit-dialog")
    expect(dlg).to_be_visible()
    expect(dlg).to_have_attribute("data-collection", "cisco.ios")
    expect(dlg.get_by_test_id("unit-body")).to_be_visible()
    # After the async GET /api/units fetch resolves, the body settles to ONE of: the unit list, the honest-empty
    # pane, or the degraded error pane (all valid honest states). expect() AUTO-WAITS for the fetch to land — a
    # plain .count() snapshot would race the spinner. A generous timeout tolerates a slow `ansible-galaxy list`.
    panes = dlg.locator('[data-testid="unit-list"], [data-testid="unit-list-empty"], [data-testid="unit-list-error"]')
    expect(panes.first).to_be_visible(timeout=15000)


def test_unit_dialog_closes(page):
    """The dialog's close control removes it — guards the modal lifecycle (an un-closable overlay would trap the
    operator on the page). Mirrors test_capability_dialog_closes."""
    page.goto("/")
    page.get_by_test_id("search-input").fill("cisco ios")
    page.get_by_test_id("search-btn").click()
    expect(page.get_by_test_id("card").first).to_be_visible()
    page.get_by_test_id("unit-badge").first.click()
    expect(page.get_by_test_id("unit-dialog")).to_be_visible()
    page.get_by_test_id("unit-close").click()
    expect(page.get_by_test_id("unit-dialog")).to_have_count(0)


def test_unit_result_renders_runid_and_staged_ref(page):
    """The create dialog's result pane reuses `renderCapPromote` (the staged-ref + run_id renderer, #126). Create is
    NOT driven here (it commits + needs an armed staging repo); instead this calls the shared renderer in the browser
    with a synthetic staged create response and asserts the run_id + the staged `proposed/<ref>` surface — so the
    operator can find the id for Semaphore's promote-proposal task. Guards the `unit-result` wiring (the create
    flow's terminal pane uses the proven renderer, not a bespoke one that could drop the id)."""
    page.goto("/")
    staged = page.evaluate(
        "() => renderCapPromote({changed:true, staged:true, target_ref:'proposed/deadbeef0001',"
        " run_id:'deadbeef0001', paths:['instance/actuation/cisco-ios-ios-facts/unit.yml']})")
    assert "deadbeef0001" in staged and "STAGED proposal proposed/deadbeef0001" in staged
    assert "Semaphore promote-proposal" in staged
