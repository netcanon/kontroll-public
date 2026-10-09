"""The standalone secondary-capability dialog, end-to-end in a headless browser over the REAL Flask app.

The seam's rendered UX (Capability-track Phase 7, docs/observability/secondary-capability-dialog.md): the
telemetry badge on a result card opens the standalone dialog, the picker offers the methods the class can add,
and PROPOSE renders the pure plan (paths + enact) WITHOUT writing. The hermetic API contract (auth, propose
purity, the token-gated promote + audit) is covered in tests/integration/test_gui_api.py; this proves the
browser actually builds and drives the dialog. Promote is deliberately NOT exercised here — it commits; this
stops at propose, which is pure (reads the real module.yml read-only). Selectors are data-testid only
(docs/testing-standards.md §3). opt-in via the `e2e` marker.
"""
import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_capability_dialog_opens_and_proposes(page):
    """Clicking the telemetry badge opens the capability dialog for the onboarded class; picking a method and
    proposing renders the PURE plan (paths + enact commands) — the seam's rendered UX and the
    propose-writes-nothing boundary, proven in a real browser. Guards the openCapabilityDialog → suggest →
    propose path actually wiring up (the Phase-7 acceptance: the dialog opens via openCapabilityDialog)."""
    page.goto("/")
    page.get_by_test_id("search-input").fill("cisco ios")
    page.get_by_test_id("search-btn").click()
    card = page.get_by_test_id("card").first
    expect(card).to_be_visible()

    # the telemetry capability badge is clickable (a secondary capability with a standalone dialog)
    card.locator('[data-testid="capability-badge"][data-cap="telemetry"]').click()
    dlg = page.get_by_test_id("cap-dialog")
    expect(dlg).to_be_visible()
    expect(dlg.get_by_test_id("cap-method")).to_be_visible()      # the Stage-1 method picker rendered

    # Stage-3 render-table (Phase 3, #137): telemetry's resource_stage (source_kind: curated_list) now RENDERS
    # its descriptor-supplied container — closing the specced-but-unbuilt gap (testid_reference §Stage-3 was
    # "rendered? no"). No curated dashboards are offered yet (suggested_dashboards is a later phase), so it
    # shows the honest empty state, not fabricated chips.
    expect(dlg.get_by_test_id("cap-telemetry-dashboards")).to_be_visible()

    dlg.get_by_test_id("cap-propose").click()
    plan = dlg.get_by_test_id("cap-plan")
    expect(plan).to_contain_text("PLAN")                          # the pure plan rendered
    expect(plan).to_contain_text("enact")                        # the operator's hand-off commands listed


def test_logging_capability_badge_opens_the_dialog(page):
    """G1 (public-readiness audit 2026-06-18): the logging capability badge is now clickable — `'logging'` was
    added to `CAP_DIALOGS` — so it opens the SAME shared, data-driven capability dialog telemetry/backup use,
    proving log rides the one dialog in the GUI (not just the backend). Guards the regression the audit caught:
    `CAP_DIALOGS` omitted `'logging'`, so the badge rendered inert and the operator had NO entry point to the
    fully-built log capability (observe-AND-log was only half-true in the GUI)."""
    page.goto("/")
    page.get_by_test_id("search-input").fill("cisco ios")
    page.get_by_test_id("search-btn").click()
    card = page.get_by_test_id("card").first
    expect(card).to_be_visible()
    badge = card.locator('[data-testid="capability-badge"][data-cap="logging"]')
    expect(badge).to_be_visible()                            # the logging badge renders on the card
    badge.click()                                            # inert before G1; now opens the shared dialog
    dlg = page.get_by_test_id("cap-dialog")
    expect(dlg).to_be_visible()
    expect(dlg).to_have_attribute("data-cap", "logging")     # the dialog is the logging instance of the shared shell


def test_logging_method_with_a_cred_surfaces_the_prereq(page):
    """G3 (public-readiness audit 2026-06-18): selecting a logging method that needs a SOPS credential surfaces an
    advisory credential-prerequisite in the capability dialog (mirroring the onboard `provisioning:` pane) — closing
    the gap where the declare-path and credential-path diverged silently (the dialog never told the operator a cred
    was needed). Guards the cap-cred-prereq render + that it names the method's secret_domain."""
    page.goto("/")
    page.get_by_test_id("search-input").fill("cisco ios")
    page.get_by_test_id("search-btn").click()
    card = page.get_by_test_id("card").first
    expect(card).to_be_visible()
    card.locator('[data-testid="capability-badge"][data-cap="logging"]').click()
    dlg = page.get_by_test_id("cap-dialog")
    expect(dlg).to_be_visible()
    # file_tail_ssh names secret_domain logging_file_tail (cisco_ios declares syslog_push, so this stays offerable)
    dlg.get_by_test_id("cap-method").select_option("file_tail_ssh")
    prereq = dlg.get_by_test_id("cap-cred-prereq")
    expect(prereq).to_be_visible()
    expect(prereq).to_contain_text("logging_file_tail")


def test_cap_promote_render_surfaces_runid_and_staged_ref(page):
    """#126: a capability promote STAGES `proposed/<run_id>` (C10) exactly like onboarding, but `capPromote`
    rendered only 'PROMOTED + committed: <paths>' — dropping BOTH the run_id AND the staged ref, so the operator
    had no way to find the id to enter in Semaphore's promote-proposal survey (the live 'where do I get the
    run_id' blocker). Promote is NOT driven here (it commits + needs an armed staging repo); instead this calls
    the extracted top-level `renderCapPromote()` directly in the browser with a synthetic staged response and
    asserts the run_id + the staged `proposed/<ref>` now appear (and the committed-to-main fallback still names
    the run_id). Guards the regression where the promote result hid the very id the operator needs — mirroring
    renderOnboard, which already surfaced it (~L219)."""
    page.goto("/")
    staged = page.evaluate(
        "() => renderCapPromote({changed:true, staged:true, target_ref:'proposed/deadbeef0001',"
        " run_id:'deadbeef0001', paths:['instance/inventory/edge.yml']})")
    assert "deadbeef0001" in staged                              # the run_id is surfaced (the operator needs it)
    assert "STAGED proposal proposed/deadbeef0001" in staged     # and the staged ref — what exactly was staged
    assert "Semaphore promote-proposal" in staged                # points the operator straight at the promote task
    committed = page.evaluate(
        "() => renderCapPromote({changed:true, staged:false, target_ref:'',"
        " run_id:'cafef00d2222', paths:['instance/inventory/edge.yml']})")
    assert "committed to main" in committed and "cafef00d2222" in committed   # un-armed dev still names the run_id


def test_capability_dialog_closes(page):
    """The dialog's close control removes it — guards the modal lifecycle (an un-closable overlay would trap
    the operator on the page)."""
    page.goto("/")
    page.get_by_test_id("search-input").fill("cisco ios")
    page.get_by_test_id("search-btn").click()
    expect(page.get_by_test_id("card").first).to_be_visible()
    page.locator('[data-testid="capability-badge"][data-cap="telemetry"]').first.click()
    expect(page.get_by_test_id("cap-dialog")).to_be_visible()
    page.get_by_test_id("cap-close").click()
    expect(page.get_by_test_id("cap-dialog")).to_have_count(0)
