"""The keygen dialog (D), end-to-end in a headless browser over the REAL Flask app. The hermetic auth + the
no-leak / show-once contract are covered by tests/integration/test_gui_api.py (keygen) + tests/unit/
test_keygen_service.py; THIS proves the rendered UX + that the new dialog JS actually runs (the integration
tests never execute the browser JS): open "Keys" → the role picker lists the registered roles → open one →
its scope + the show-once WARNING + the Generate button render. It stops BEFORE clicking Generate — the GET
routes touch no age-keygen and never write /.sops.yaml (they read the descriptor + derive the recipient
domains), so this needs no key mocks and mints nothing. Selectors are data-testid only (testid_reference.md).
opt-in via the `e2e` marker.
"""
import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_keygen_picker_and_dialog_render(page):
    """Clicking "Keys" opens the picker (one button per registered role); opening a role renders its scope,
    the show-once warning, and the Generate button. Guards the keygen dialog's open→list→open→render path +
    the new dialog JS loading cleanly (a template JS syntax error would surface here as an empty/broken modal).
    It deliberately does NOT click Generate (that would mint a key + edit /.sops.yaml)."""
    page.goto("/")
    page.get_by_test_id("keygen-open").click()
    expect(page.get_by_test_id("keygen-picker-body")).to_be_visible()
    bg = page.locator('[data-testid="keygen-role"][data-role="break-glass"]')
    expect(bg).to_be_visible()

    bg.click()
    body = page.get_by_test_id("keygen-body")
    expect(body).to_be_visible()
    # the break-glass descriptor carries a show-once warning + a Generate button (the mint trigger)
    expect(body.get_by_test_id("keygen-warning")).to_be_visible()
    expect(body.get_by_test_id("keygen-generate")).to_be_visible()
