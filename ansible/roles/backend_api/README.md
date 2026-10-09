# role: backend_api

**Execution backend**, not a device class. Generic `check`/`backup` for REST/API
devices **and services** (FortiGate, OPNsense, the Servarr apps, …), driven by a
per-API **recipe** (`ansible/backends/api/recipes/<name>.yml`) — auth + endpoints
as data. Uses plain `ansible.builtin.uri` delegated to localhost: **no vendor
module, no httpapi plugin, no collection required**. One role, N recipes — this is
how the API tail folds into data instead of a role per vendor (capability-matrix §5.2).

The generalization of the proven `roles/fortigate` capture: `fortigate` is now a
thin wrapper that points here with `backend_api_recipe: fortios`. Verified live —
the generic capture is byte-for-byte the FortiGate full-configuration (differing
only in FortiOS's per-export re-encrypted secret blobs).

## Entrypoints (`tasks_from`)

| Entrypoint | Purpose | Blast radius |
|---|---|---|
| `check`  | liveness via the recipe's `check.path` (read-only GET) | none |
| `backup` | capture via the recipe's `backup` endpoint, writes the body | none (read-only) |

## Params (set by the device class)
- `backend_api_recipe` — **required**: the recipe name under `backends/api/recipes/`.
- `backend_backup_label` — filename prefix fallback (recipe `backup.label` wins).

## Recipe schema (`backends/api/recipes/<name>.yml`)
Pure data, secret-free — the token is **named** (`auth.token_var`) and resolved from
the host's SOPS-backed vars at runtime, never inlined.

```yaml
name: fortios
port: 443
validate_certs: false
auth:   {type: bearer, token_var: fortios_api_token}   # bearer | basic | apikey_header
check:  {method: GET, path: /api/v2/monitor/system/status}
backup: {method: GET, path: /api/.../config/backup, extract: body,
         label: FortiGate, suffix: full-configuration.conf}
```

Auth types: `bearer` (`Authorization: Bearer <token>`), `apikey_header`
(`<header_name>: <token>`), `basic` (`username_var`/`password_var`). Backup
endpoints must be **read-only** (GET / export). Output is `no_log` — the request
carries the token, the response the secret-bearing config.

## See also
- [../../backends/api/backend.yml](../../backends/api/backend.yml) — classifier metadata
- [../../backends/api/recipes/](../../backends/api/recipes/) — the recipe registry (drop-in)
- [../fortigate/README.md](../fortigate/README.md) — the device class that wraps this
- [../../../docs/capability-matrix.md](../../../docs/capability-matrix.md) — the design (§5.2 the API tail)
