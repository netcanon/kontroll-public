"""E2E — the discovery inbox + the onboard host pre-fill (discovery-inbox Rung 1b).

WHY: the whole rung exists to FEED the existing human onboard flow from a passive lease view, so these prove the two
load-bearing properties in a REAL browser that no unit test can: (F6) a device-controlled hostname renders as
literal TEXT — a `<script>` in a lease never executes in the operator's authenticated session (a lease is
attacker-influenceable; ET/textContent is the structural block); and the "Onboard this" pre-fill lands the
discovered host into the EXISTING onboard form's host field, after which the human still picks the class + fills
creds + clicks Run (C10 — there is NO auto-onboard). The inbox read is mocked in conftest
(`kontroll.service.discovery.read_inbox` → two candidates, one with a `<script>` hostname); the onboard form is the
real one `search` renders (cisco.ios, via the conftest shallow-search mock).
"""
import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _open_discovery(page):
    page.goto("/")
    page.get_by_test_id("discovery-open").click()
    expect(page.get_by_test_id("discovery-panel")).to_be_visible()


def test_discovery_panel_lists_uncorrelated_hosts(page):
    """The panel renders one discovery-row per un-onboarded candidate + the swept-provenance signpost — so the
    operator sees what the network has that they haven't onboarded (the read view, C18)."""
    _open_discovery(page)
    expect(page.get_by_test_id("discovery-swept")).to_contain_text("last swept")
    expect(page.get_by_test_id("discovery-row")).to_have_count(2)
    expect(page.get_by_test_id("discovery-row").first).to_contain_text("sw-lab-3")


def test_discovery_hostname_renders_as_text_not_script(page):
    """A candidate hostname of `<script>…</script>` renders as LITERAL TEXT and never executes (F6). Proven both
    ways: the literal string is present in the panel text AND the script's side effect (`window.__xss`) never fired.
    Guards the attacker-influenceable-lease → XSS path structurally (the ET/textContent rule, verbatim from C14)."""
    _open_discovery(page)
    expect(page.get_by_test_id("discovery-body")).to_contain_text("<script>window.__xss=1</script>")
    assert page.evaluate("() => window.__xss === undefined"), "the lease `<script>` hostname EXECUTED (XSS)"


def test_onboard_this_prefills_the_host_into_the_onboard_form(page):
    """Clicking a row's 'Onboard this' stashes the discovered host + shows the (clearable) banner; after the operator
    searches and opens the resulting card's onboard form, its host field is PRE-FILLED with the discovered IP AND its
    inventory-name field with the discovered hostname — the seam the whole rung exists for. The human still picks the
    class + fills creds; `apply` stays unchecked (dry-run first, the human floor) — discovery never onboards/stages (C10)."""
    _open_discovery(page)
    page.get_by_test_id("discovery-row").first.get_by_test_id("discovery-onboard").click()
    expect(page.get_by_test_id("discovery-prefill-banner")).to_contain_text("192.0.2.42")
    # the operator searches + picks the device class (Rung 1 doesn't guess it), then opens the onboard form
    page.get_by_test_id("search-input").fill("cisco")
    page.get_by_test_id("search-btn").click()
    page.get_by_test_id("onboard-toggle").first.click()
    form = page.get_by_test_id("onboard-form").first
    expect(form.get_by_test_id("field-host")).to_have_value("192.0.2.42")
    expect(form.get_by_test_id("field-host-name")).to_have_value("sw-lab-3")   # the discovered hostname pre-fills the inventory name
    expect(form.get_by_test_id("field-apply")).not_to_be_checked()


def test_discovery_vendor_hint_renders_as_advisory_text(page):
    """The OUI vendor hint (Rung 3) renders as advisory `discovery-vendor` text on a candidate that has one, and is
    ABSENT on a candidate whose MAC had no OUI match (vendor None). WHY: proves the display hint reaches the row via
    ET/textContent (never innerHTML) and is truly optional — the whole rung is a recognition aid, not a required field."""
    _open_discovery(page)
    expect(page.get_by_test_id("discovery-vendor")).to_have_count(1)         # only the one candidate with a vendor
    expect(page.get_by_test_id("discovery-vendor")).to_contain_text("IEEE Example Vendor Inc")


def test_onboard_this_prefills_only_the_host_never_a_class(page):
    """THE un-regressable F8 guard (Rung 3): clicking 'Onboard this' on a row that carries a vendor hint pre-fills ONLY
    the host — the search box is EMPTY and no device class is pre-selected. WHY: a MAC's OUI is a manufacturer, not an
    Ansible collection; F8 cut the vendor class-GUESS. This test fails loudly if a future contributor ever wires the
    vendor into class selection / card synthesis (re-opening the auto-onboard door), so the display-hint stays a
    display hint. The human still searches + picks the class (C10)."""
    _open_discovery(page)
    page.get_by_test_id("discovery-row").first.get_by_test_id("discovery-onboard").click()
    expect(page.get_by_test_id("discovery-prefill-banner")).to_contain_text("192.0.2.42")
    # the vendor hint did NOT seed a search or a class: the search box is empty + NO onboard form is pre-rendered
    expect(page.get_by_test_id("search-input")).to_have_value("")
    expect(page.get_by_test_id("onboard-form")).to_have_count(0)             # no class card synthesized from the OUI


def test_discovery_prefill_clears(page):
    """The banner's 'clear' resets the stash — a later onboard form is NOT silently pre-filled with a stale host
    (the stash is always visible + dismissible, never silent)."""
    _open_discovery(page)
    page.get_by_test_id("discovery-row").first.get_by_test_id("discovery-onboard").click()
    banner = page.get_by_test_id("discovery-prefill-banner")
    expect(banner).to_be_visible()
    banner.get_by_test_id("discovery-prefill-clear").click()
    expect(banner).to_be_hidden()
