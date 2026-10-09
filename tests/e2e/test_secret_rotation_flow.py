"""The secret-rotation UI gate + actuation hand-off (PR-1, #141), exercised in a real browser via
`page.evaluate` over the top-level pure functions (the `reconfigGate`/`renderReconfigDiff` precedent in
test_reconfigure_flow.py). WHY (the failures these guard): rotating a service password CLOBBERS a live secret
— the danger is a SILENT overwrite — and the staged value is NOT live until the operator runs a post-promote
step. The defences the operator sees are (a) `secretOverwriteGate` rendering a NAMES-only
`secret-overwrite-confirm` (the operator-facing half of the C9 gate the SERVER already enforced as a
fail-closed 409), and (b) `renderSecretEnact` printing the actuation hand-off as command STRINGS — never a
value, and the GUI executes none of it. Selectors / returned-node only; opt-in via the `e2e` marker.
"""
import pytest

pytestmark = pytest.mark.e2e


def test_secret_overwrite_gate_renders_names_only_confirm(page):
    """secretOverwriteGate renders a `secret-overwrite-confirm` row + a `secret-overwrite-go` button listing the
    field NAMES being clobbered — never a value. The operator-facing half of the C9 overwrite gate; the server is
    the real guard (it 409'd WITHOUT writing). Guards the confirm element existing + carrying NAMES only."""
    page.goto("/")
    r = page.evaluate("""() => {
        const dlg = document.createElement('div');
        dlg.innerHTML = '<div class="capbody"><pre data-testid="secret-result"></pre></div>';
        document.body.appendChild(dlg);
        const out = dlg.querySelector('[data-testid=secret-result]');
        secretOverwriteGate(dlg, ['gui_admin_password','grafana_admin_password'], out);
        const confirm = dlg.querySelector('[data-testid=secret-overwrite-confirm]');
        const go = dlg.querySelector('[data-testid=secret-overwrite-go]');
        const txt = out.textContent + ' ' + (go ? go.textContent : '');
        dlg.remove();
        return {hasConfirm: !!confirm, hasGo: !!go, txt};
    }""")
    assert r["hasConfirm"] and r["hasGo"]
    assert "gui_admin_password" in r["txt"] and "grafana_admin_password" in r["txt"]


def test_secret_enact_renders_handoff_without_value(page):
    """renderSecretEnact prints the post-promote actuation hand-off (field + command string + consequence) into a
    `secret-enact` pane built from the server's NAMES+cmds records — the GUI executes none of it and NO secret
    value appears. Guards the hand-off rendering + the C11 no-value contract at the UI."""
    page.goto("/")
    r = page.evaluate("""() => {
        const dlg = document.createElement('div');
        dlg.innerHTML = '<div class="capbody"></div>';
        document.body.appendChild(dlg);
        renderSecretEnact(dlg, [{field:'gui_admin_password', kind:'operator',
            cmd:'cd ~/kontroll/ansible && ansible-playbook playbooks/deploy-stack.yml -e stack',
            why:'recreate onboard-gui', consequence:'self-evict'}]);
        const pane = dlg.querySelector('[data-testid=secret-enact]');
        const txt = pane ? pane.textContent : '';
        dlg.remove();
        return {hasPane: !!pane, txt};
    }""")
    assert r["hasPane"]
    assert "gui_admin_password" in r["txt"] and "deploy-stack" in r["txt"] and "self-evict" in r["txt"]


def test_secret_enact_empty_renders_nothing(page):
    """An empty enact list (a stage-only field, e.g. Semaphore admin in PR-1) renders NO `secret-enact` pane — no
    spurious 'to apply' box when there is nothing to actuate. Guards a confusing empty hand-off for stage-only."""
    page.goto("/")
    r = page.evaluate("""() => {
        const dlg = document.createElement('div');
        dlg.innerHTML = '<div class="capbody"></div>';
        document.body.appendChild(dlg);
        renderSecretEnact(dlg, []);
        const pane = dlg.querySelector('[data-testid=secret-enact]');
        dlg.remove();
        return {hasPane: !!pane};
    }""")
    assert r["hasPane"] is False
