# instance/secrets/ — SOPS-encrypted secret domains (NEVER shipped)

This directory holds your encrypted `*.sops.yml` secret files — one per domain
(`network`, `proxmox`, `dashboards`, `semaphore`, …). **The tool ships none of them**,
and `kontroll-init --fresh` copies none into your overlay. They are created on YOUR
node, encrypted to YOUR key (the recipient in `instance/.sops.yaml`), by either:

- **`kontroll-init --fresh`** — mints the bootstrap `dashboards` secrets (the onboard-GUI
  + Grafana login passwords and the API token); or
- the **onboard-GUI "Secrets" dialog** — guided, no-leak entry per domain; or
- `sops instance/secrets/<domain>.sops.yml` directly (type values into the editor — never
  on the command line; SECURITY.md C11).

After you add a recipient (break-glass or the scoped Semaphore key), re-wrap so the
existing files gain it:

```bash
sops --config instance/.sops.yaml updatekeys instance/secrets/*.sops.yml
```

Never commit a plaintext secret or an age private key. See `SECURITY.md` (C8 / C11).
