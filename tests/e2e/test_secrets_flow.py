"""The secret-onboarding dialog (D), end-to-end in a headless browser over the REAL Flask app. The hermetic
auth + no-leak contract is covered by tests/integration/test_gui_api.py + test_api_secrets.py; THIS proves the
rendered UX + that the new dialog JS actually runs (the integration tests never execute the browser JS): open
"Secrets" → the domain picker lists the registered domains → open one → its fields render. The GET routes touch
no sops/age (they read the descriptor + the domain's key NAMES), so this needs no extra secret mocks. Selectors
are data-testid only (testid_reference.md). opt-in via the `e2e` marker.
"""
import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_secrets_picker_and_dialog_render(page):
    """Clicking "Secrets" opens the picker (one button per registered domain); opening a domain renders its
    field inputs. Guards the secret dialog's open→list→open→render path + the new dialog JS loading cleanly
    (a template JS syntax error would surface here as an empty/broken modal)."""
    page.goto("/")
    page.get_by_test_id("secrets-open").click()
    expect(page.get_by_test_id("secret-picker-body")).to_be_visible()
    dash = page.locator('[data-testid="secret-domain"][data-domain="dashboards"]')
    expect(dash).to_be_visible()

    dash.click()
    body = page.get_by_test_id("secret-body")
    expect(body).to_be_visible()
    # the dashboards descriptor declares grafana_admin_password — its input renders by data-field
    expect(body.locator('[data-testid="secret-field"][data-field="grafana_admin_password"]')).to_be_visible()
    expect(body.get_by_test_id("secret-apply")).to_be_visible()


def test_logging_file_tail_key_renders_a_textarea(page):
    """G2 (public-readiness audit 2026-06-18): the file_tail_ssh SSH private key (logging_file_tail) is now
    GUI-supplyable — its secret form's `type: textarea` field renders a MULTI-LINE <textarea> (a single-line
    <input> can't hold a PEM). Closes the gap where the operator had to hand-`sops` the key. Guards the new
    textarea field-type render + that the key is addressable by data-field."""
    page.goto("/")
    page.get_by_test_id("secrets-open").click()
    dom = page.locator('[data-testid="secret-domain"][data-domain="logging_file_tail"]')
    expect(dom).to_be_visible()                              # the new domain is listed in the picker
    dom.click()
    body = page.get_by_test_id("secret-body")
    expect(body).to_be_visible()
    field = body.locator('[data-testid="secret-field"][data-field="ssh_private_key"]')
    expect(field).to_be_visible()
    assert field.evaluate("el => el.tagName.toLowerCase()") == "textarea"   # multi-line, not a single-line input
