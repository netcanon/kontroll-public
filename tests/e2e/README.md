# tests/e2e — end-to-end proofs

Two end-to-end surfaces live here:
1. **The non-human onboarding proof** (ansible; `inventory.yml`) — below.
2. **The GUI flow** (Playwright; `conftest.py` + `test_onboard_flow.py`, the `e2e` marker) —
   see [GUI flow](#gui-flow-playwright).

## The non-human onboarding proof — the path

1. `galaxy.py search cisco.ios` → labels it `backup:✓`, suggests `netcommon_cli`.
2. `galaxy.py scaffold cisco.ios --key ios_xe_auto --group core_switch`
   → `modules/ios_xe_auto/module.yml` (machine-authored; `role: backend_netcommon_cli`).
3. A host is added to `inventory.yml` under that class + credentials supplied.
4. The **standard** dispatch (`backup-configs.yml`) runs the **generic**
   `backend_netcommon_cli` backend (`ansible.netcommon.cli_command`) against the
   live device — **no `cisco.ios.ios_command`, no hand-written Cisco task**.

The result is a real running-config capture, byte-identical to what the
hand-written `cisco_ios` role produced. That is the proof that "search → it can
back up → provide creds → get a backup" is fully automatable.

## Run

```bash
cd ansible
ansible-playbook playbooks/backup-configs.yml \
  -i ../tests/e2e/inventory.yml --limit ios-xe-auto-test
# capture appears in tests/e2e/_out/ (gitignored — holds secrets)
```

## GUI flow (Playwright)

`test_onboard_flow.py` drives the onboarding GUI in a **headless browser over the REAL Flask
app** — `conftest.py` boots `gui/app.py` in a daemon thread with the service I/O seams mocked (no
galaxy.py, no ansible, no lab) and supplies HTTP Basic creds via the browser context. It proves
the rendered UX: **search → result card → open the form → dry-run → the plan renders**. The
hermetic auth/contract is covered by [test_gui_api.py](../integration/test_gui_api.py); this is
the browser layer on top.

```bash
pip install -r tests/requirements-dev.txt        # includes pytest-playwright
python -m playwright install chromium             # one-time browser fetch
pytest tests/e2e -m e2e                           # headless
```

Opt-in (the `e2e` marker is excluded from the hermetic default); a dedicated GitHub Actions job
(`e2e` in `.github/workflows/ci.yml`) runs it headless on every push/PR — cost $0 within the
private-repo Actions free tier.

## See also
- [../../docs/capability-matrix.md](../../docs/capability-matrix.md) — the design
- [../../ansible/roles/backend_netcommon_cli/](../../ansible/roles/backend_netcommon_cli/) — the generic backend
- [../../modules/ios_xe_auto/module.yml](../../modules/ios_xe_auto/module.yml) — the scaffolded class
