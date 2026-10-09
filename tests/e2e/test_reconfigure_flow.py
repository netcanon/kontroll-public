"""The safe-reconfigure UI (Phase 4a, #138), exercised in a real browser via `page.evaluate` over the top-level
pure functions (the `renderCapPromote`/`renderReconfigDiff` precedent). WHY (the failures these guard): goal-2
makes "change a knob of an already-configured object" routine, and the danger is a SILENT value-clobber. The
defence the operator sees is (a) the `reconfig-diff` pane showing the field-level change BEFORE anything stages,
and (b) the severity GATE that keeps Promote DISABLED until the overwrite is explicitly confirmed. These prove
both: the diff renders the modify/add/remove change-set, and `capReconfigGate` disables Promote for a clobber
until `reconfig-overwrite-confirm` is acknowledged (a benign add enables it directly). Selectors/structure of
the returned node only. opt-in via the `e2e` marker.
"""
import pytest

pytestmark = pytest.mark.e2e


def test_reconfig_diff_renders_the_change_set(page):
    """renderReconfigDiff renders a modify with before→after (flagged OVERWRITES), an add, and a remove, and
    counts the clobbering changes. Guards the operator seeing EXACTLY what changes (value-aware) before staging —
    a modify is never shown as a benign add."""
    page.goto("/")
    out = page.evaluate("""() => renderReconfigDiff([
        {path:'backup.retention', kind:'modify', before:'keep-all', after:'90d'},
        {path:'backup.destination', kind:'add', after:'local'},
        {path:'metrics.icmp', kind:'remove', before:{}},
    ])""")
    assert "backup.retention" in out and "keep-all" in out and "90d" in out and "OVERWRITES" in out
    assert "metrics.icmp" in out and "DROPS" in out
    assert "this changes 2 existing values" in out               # modify + remove are the clobbering ones


def test_reconfig_gate_disables_promote_until_overwrite_confirmed(page):
    """capReconfigGate, given a `modify` change-set, renders the reconfig-diff pane, keeps Promote DISABLED, and
    shows a reconfig-overwrite-confirm control; clicking it enables Promote. THE non-bypassable confirm: a value
    clobber cannot be promoted until the operator acknowledges it."""
    page.goto("/")
    r = page.evaluate("""() => {
        const dlg = document.createElement('div');
        dlg.innerHTML = '<div class="capbody"><button data-testid="cap-promote" disabled>Promote</button></div>';
        document.body.appendChild(dlg);
        capReconfigGate(dlg, {changes:[{path:'backup.retention', kind:'modify', before:'keep-all', after:'90d'}]});
        const promote = dlg.querySelector('[data-testid=cap-promote]');
        const confirm = dlg.querySelector('[data-testid=reconfig-overwrite-confirm]');
        const before = promote.disabled, diff = !!dlg.querySelector('[data-testid=reconfig-diff]');
        confirm.click();
        const after = promote.disabled;
        dlg.remove();
        return {before, after, diff, hasConfirm: !!confirm};
    }""")
    assert r["diff"] and r["hasConfirm"]
    assert r["before"] is True and r["after"] is False           # gated, then enabled after the confirm


def test_reconfig_gate_enables_promote_for_a_pure_add(page):
    """An add-only change-set (a new method) enables Promote DIRECTLY with NO confirm — a first-write is
    co-owner-safe and flows exactly as before (backward-compatible). Guards the gate over-blocking a benign add."""
    page.goto("/")
    r = page.evaluate("""() => {
        const dlg = document.createElement('div');
        dlg.innerHTML = '<div class="capbody"><button data-testid="cap-promote" disabled>Promote</button></div>';
        document.body.appendChild(dlg);
        capReconfigGate(dlg, {changes:[{path:'host_node', kind:'add', after:{}}]});
        const promote = dlg.querySelector('[data-testid=cap-promote]');
        const r = {disabled: promote.disabled, hasConfirm: !!dlg.querySelector('[data-testid=reconfig-overwrite-confirm]')};
        dlg.remove();
        return r;
    }""")
    assert r["disabled"] is False and r["hasConfirm"] is False     # add → Promote enabled, no confirm


# --- Phase 4b (#139): the heavier severities + the generalized gate over an arbitrary promote button ----------- #
def test_reconfig_diff_renders_identity_and_redeploy_glyphs(page):
    """renderReconfigDiff keys off the EFFECTIVE severity (c.severity || c.kind): an `identity` change shows the
    ⚑ glyph + 'IDENTITY — re-classifies' + its blast_radius; a `redeploy` shows 'live only after deploy-stack'.
    Guards a re-classify / redeploy being shown as a plain modify (the operator under-reading the blast)."""
    page.goto("/")
    out = page.evaluate("""() => renderReconfigDiff([
        {path:'inventory_group', kind:'modify', before:'core_switch', after:'edge_firewall', severity:'identity', blast_radius:'re-home-hosts'},
        {path:'tls_mode', kind:'modify', before:'byo_proxy', after:'self_signed', severity:'redeploy'},
    ])""")
    assert "IDENTITY" in out and "re-home-hosts" in out and "edge_firewall" in out
    assert "redeploy" in out and "deploy-stack" in out


def test_reconfig_gate_identity_requires_type_to_confirm(page):
    """reconfigGate, given an `identity` change, renders a reconfig-identity-confirm INPUT and keeps the promote
    button DISABLED until the typed value EXACTLY equals the new value (the type-to-confirm gate, mirroring the
    mgmt-IP guard). THE non-bypassable identity gate: a re-home cannot be promoted by a stray click — the operator
    must retype the new value."""
    page.goto("/")
    r = page.evaluate("""() => {
        const dlg = document.createElement('div');
        dlg.innerHTML = '<div class="capbody"><button data-testid="reconfig-promote" disabled>Promote</button></div>';
        document.body.appendChild(dlg);
        const promote = dlg.querySelector('[data-testid=reconfig-promote]');
        reconfigGate(dlg, [{path:'inventory_group', kind:'modify', before:'core_switch', after:'edge_firewall', severity:'identity', blast_radius:'re-home-hosts'}], promote);
        const inp = dlg.querySelector('[data-testid=reconfig-identity-confirm]');
        const gated = promote.disabled;
        inp.value = 'wrong'; inp.dispatchEvent(new Event('input'));
        const afterWrong = promote.disabled;
        inp.value = 'edge_firewall'; inp.dispatchEvent(new Event('input'));
        const afterRight = promote.disabled;
        dlg.remove();
        return {hasInput: !!inp, gated, afterWrong, afterRight};
    }""")
    assert r["hasInput"] and r["gated"] is True
    assert r["afterWrong"] is True and r["afterRight"] is False     # only an EXACT retype enables Promote


def test_reconfig_gate_redeploy_requires_ack(page):
    """A `redeploy`-severity change gates the promote behind a reconfig-redeploy-confirm ACK (not a type-to-
    confirm). Guards a redeploy-needing change staging without the operator acknowledging it only goes live after
    deploy-stack."""
    page.goto("/")
    r = page.evaluate("""() => {
        const dlg = document.createElement('div');
        dlg.innerHTML = '<div class="capbody"><button data-testid="reconfig-promote" disabled>Promote</button></div>';
        document.body.appendChild(dlg);
        const promote = dlg.querySelector('[data-testid=reconfig-promote]');
        reconfigGate(dlg, [{path:'tls_mode', kind:'modify', before:'byo_proxy', after:'self_signed', severity:'redeploy'}], promote);
        const ack = dlg.querySelector('[data-testid=reconfig-redeploy-confirm]');
        const before = promote.disabled; ack.click(); const after = promote.disabled;
        dlg.remove();
        return {hasAck: !!ack, before, after};
    }""")
    assert r["hasAck"] and r["before"] is True and r["after"] is False
