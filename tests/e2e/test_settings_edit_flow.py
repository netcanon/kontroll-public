"""The Settings EDIT entry controls (Phase 5, #140), exercised in a real browser via `page.evaluate` over the
row renderers (the established pure-function pattern). WHY (the failures these guard): Phase 5 makes the Phase-1
read-only Settings panel EDITABLE, and the entry points are the per-knob `edit` controls + the per-module
`disable` controls that open the SHARED reconfigure dialog (whose severity gate — mgmt_ip type-to-confirm,
fleet-removal remove-confirm — is already e2e-pinned by test_reconfigure_flow). These prove the panel emits those
controls with the right discriminators (so Playwright/an operator can target one), that a DANGER knob is flagged,
and that a SURFACE knob (source_of_truth) is NOT editable. Selectors/structure only; opt-in via the `e2e` marker.
"""
import pytest

pytestmark = pytest.mark.e2e


def test_settings_identity_rows_render_per_knob_edit_controls(page):
    """settingsIdentityRows renders an `edit` control (settings-knob-edit) for each EDITABLE identity knob, flags
    the danger knobs (mgmt_ip/domain/tls_mode carry ⚠), and renders source_of_truth read-only (SURFACE — NO edit
    control). Guards a danger knob shipping without its warning, or the read-only mode gaining an editor."""
    page.goto("/")
    r = page.evaluate("""() => {
        const g = document.createElement('div'); g.className = 'card'; document.body.appendChild(g);
        settingsIdentityRows(g, {mgmt_ip:'192.0.2.50', domain:'a.test', tls_mode:'self_signed', source_of_truth:'local'});
        const edits = [...g.querySelectorAll('[data-testid=settings-knob-edit]')].map(b => b.dataset.knob);
        const mgmt = g.querySelector('[data-testid=settings-knob][data-knob=mgmt_ip]');
        const sotEditable = !!g.querySelector('[data-testid=settings-knob][data-knob=source_of_truth]');
        const r = {edits, danger: mgmt.textContent.includes('⚠'), sotEditable};
        g.remove(); return r;
    }""")
    assert r["edits"] == ["mgmt_ip", "domain", "tls_mode"]        # the three editable identity knobs
    assert r["danger"] is True and r["sotEditable"] is False      # mgmt_ip flagged danger; source_of_truth read-only


def test_settings_fleet_rows_render_per_module_disable_controls(page):
    """settingsFleetRows renders a `disable` control (settings-fleet-disable) per active module + the read-only
    add-hint (adding is left to Onboard). Guards a missing per-module removal control or an accidental add control
    in Settings (which would bypass the #124 reuse path)."""
    page.goto("/")
    r = page.evaluate("""() => {
        const g = document.createElement('div'); document.body.appendChild(g);
        settingsFleetRows(g, {enabled_modules:['proxmox','cisco_ios']});
        const dis = [...g.querySelectorAll('[data-testid=settings-fleet-disable]')].map(b => b.dataset.module);
        const hint = !!g.querySelector('[data-testid=settings-fleet-add-hint]');
        g.remove(); return {dis, hint};
    }""")
    assert r["dis"] == ["proxmox", "cisco_ios"] and r["hint"] is True


def test_reconfig_gate_renders_the_consequence_pane_above_the_diff(page):
    """reconfigGate, given a `consequence` (the descriptor confirm_text a settings GUARD knob returns), renders a
    `reconfig-consequence` warning pane ABOVE the diff — so the operator reads the re-IP-disconnect blast BEFORE
    the type-to-confirm. Guards the one un-pinned client render step the review flagged (R1): a refactor could
    drop the pane and keep every service/route test green, silently hiding the consequence."""
    page.goto("/")
    r = page.evaluate("""() => {
        const dlg = document.createElement('div');
        dlg.innerHTML = '<div class="capbody"><button data-testid="reconfig-promote" disabled>Promote</button></div>';
        document.body.appendChild(dlg);
        const promote = dlg.querySelector('[data-testid=reconfig-promote]');
        reconfigGate(dlg, [{path:'mgmt_ip', kind:'modify', before:'192.0.2.50', after:'192.0.2.77', severity:'identity'}],
                     promote, 'Changing the management IP — YOUR CURRENT SESSION WILL DISCONNECT — reconnect at the new IP.');
        const c = dlg.querySelector('[data-testid=reconfig-consequence]');
        const diff = dlg.querySelector('[data-testid=reconfig-diff]');
        // the consequence node exists, names the disconnect, and precedes the diff in the DOM
        const order = c && diff ? (c.compareDocumentPosition(diff) & Node.DOCUMENT_POSITION_FOLLOWING) : 0;
        const r = {hasC: !!c, text: c ? c.textContent : '', before: !!order};
        dlg.remove(); return r;
    }""")
    assert r["hasC"] and "DISCONNECT" in r["text"] and r["before"] is True   # pane present, names the blast, above the diff
