# instance.example/ — the instance overlay TEMPLATE (shipped; generic)

`kontroll` is a **tool**; everything that makes a deployment *yours* — your secrets,
your age recipients, your inventory, your management IP and domain, your fleet
selection — lives in a private **`instance/` overlay** that the tool reads in
preference to its shipped defaults (resolver: `scripts/kontroll/paths.py`).

This `instance.example/` tree is the **placeholder skeleton** of that overlay. It
ships with the tool so a fresh operator has a working shape to fill in. It contains
**no real secrets and no real recipients** — only RFC 5737 / RFC 2606 documentation
placeholders (`192.0.2.x`, `example.com`) and one obviously-fake age recipient.

## Standing up your overlay

The guided path mints your control key and personalizes this skeleton in one step:

```bash
python3 scripts/kontroll-init.py --fresh --mgmt-ip <your-mgmt-ip> --domain <your-domain>
```

`--fresh`:

1. copies this skeleton to `instance/` (never overwriting an existing file, never
   copying secret ciphertext — there is none to copy);
2. mints your control age key (`~/.config/sops/age/keys.txt`, 0600);
3. writes `instance/.sops.yaml` naming **only your key** — it never inherits another
   instance's recipients (the placeholder below is *replaced*, not appended to);
4. fills `instance/instance.yml`'s `mgmt_ip` / `domain` from the flags (or leave them
   and edit by hand);
5. mints the bootstrap `dashboards` login secrets, encrypted to your key.

Add the break-glass and scoped-Semaphore keys afterward via the GUI **Keys** dialog
(or `docs/SETUP.md` §5.2), then re-wrap:

```bash
sops --config instance/.sops.yaml updatekeys instance/secrets/*.sops.yml
```

## Layout

| Path | What it is |
|---|---|
| `.sops.yaml` | SOPS creation rules — which age key encrypts which domain. **Replace the placeholder recipient.** |
| `instance.yml` | source-of-truth mode, `mgmt_ip` / `domain`, backup remotes, frontend `tls_mode`. |
| `fleet.yml` | which device-class modules this instance runs (`enabled_modules`). |
| `inventory/hosts.yml` | your hosts, in FUNCTIONAL groups (`edge_firewall`, `core_switch`, …). |
| `secrets/` | your encrypted `*.sops.yml` — **created on your node, never shipped** (see its README). |
| `dashboards/homepage/` | the Homepage portal tiles/settings — edit for your services. |
| `leak-tokens.example.txt` → `leak-tokens.txt` | the names that identify YOUR deployment (hostnames, domain, user names), one regex per line; `tests/_leak_guard.py` fails the gate if any appears in a file that ships publicly. Ships with synthetic canaries; `--fresh` copies it under its live name for you to fill in. |

A checkout with **no `instance/` at all** (a fresh clone, CI) reads this skeleton through the same
resolver (`kontroll.paths.resolve`, read-only — writers never target it), so the generators'
`--check` gates and the test suite run against these TEST-NET placeholders.

See `docs/SETUP.md`, `docs/install-from-scratch.md`, and `SECURITY.md` (C11).
