"""The MF-5 supply-chain provenance surface, end-to-end in a headless browser over the REAL Flask app.

The seam's rendered UX: the Index panel grows a fourth **Supply chain** section (`GET /api/provenance`) that lists
each collection's install provenance, marking an `unsigned-pinned` collection with an AMBER badge + the honest
"verified by pin + checksum" note — so a green "installed" never implies a signature was checked (MF-5: no
verification theatre). The hermetic contract (auth, the read round-trip, the audit, available:false) is covered in
`tests/integration/test_gui_api.py`; this proves the browser BUILDS the section + renders the amber badge. One
canned `unsigned-pinned` collection is mocked at `service/provenance.fleet_provenance` (conftest). Selectors are
`data-testid` only. opt-in via the `e2e` marker.
"""
import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_supply_chain_section_renders_amber_unsigned_pinned(page):
    """Index → the Supply chain section renders a provenance row whose badge is the AMBER `unsigned-pinned` class —
    the MF-5 surface proven in a real browser (a green 'installed' must visibly carry the unsigned-pinned class on
    the 0-signature fleet). expect() AUTO-WAITS the async /api/provenance fetch (never a .count() race)."""
    page.goto("/")
    page.get_by_test_id("fleet-open").click()
    row = page.get_by_test_id("provenance-row").first
    expect(row).to_be_visible(timeout=15000)                  # the section fetch resolved → a collection row landed
    expect(row).to_have_attribute("data-name", "community.docker")
    badge = row.get_by_test_id("provenance-class")
    expect(badge).to_have_attribute("data-class", "unsigned-pinned")
    expect(badge).to_contain_text("unsigned-pinned")


def test_supply_chain_images_subpanel_renders_amber_digest_pinned(page):
    """Index → the Supply chain section's IMAGES sub-panel (C1, §7.3) renders an image row whose badge is the AMBER
    `digest-pinned` class — proving in a real browser that a digest-pin is shown honestly (Docker-verified on pull,
    NOT a signature). expect() AUTO-WAITS the async /api/image-provenance fetch (never a .count() race)."""
    page.goto("/")
    page.get_by_test_id("fleet-open").click()
    row = page.get_by_test_id("image-provenance-row").first
    expect(row).to_be_visible(timeout=15000)                  # the images sub-panel fetch resolved → an image row landed
    expect(row).to_have_attribute("data-name", "kontroll-control")
    badge = row.get_by_test_id("image-provenance-class")
    expect(badge).to_have_attribute("data-class", "digest-pinned")
    expect(badge).to_contain_text("digest-pinned")
