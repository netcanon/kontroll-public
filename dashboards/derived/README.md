# dashboards/derived — the DERIVED dashboard-floor pins (north-star Rung 4a)

One `<method>.lock.yml` per telemetry method that carries a `derive_dashboard:` selector. Each lock is the frozen
result of **DERIVING** a grafana.com community board — **even its `id`** — from the parseable public registry, so the
dashboard floor obeys the [no-bespoke tenet](../../CLAUDE.md) (derive → pin → `--check`, churn = a reviewable diff)
exactly as the metrics/logs floor does. An operator never types `gnet: 1860`; they declare *intent* (a search query
+ datasource + a required series) on the telemetry descriptor and the engine derives the concrete id+revision+bytes.

These locks are **build-time pins, NOT runtime artifacts** — Grafana loads the committed board JSON in
[../grafana/dashboards/](../grafana/dashboards/), never these files.

## The chain

```
telemetry/<method>.yml  derive_dashboard: {search, datasource, requires_series, prefer_gnet?, name?}
        │
        ▼   scripts/gen-dashboard-floor.py --resolve   (NETWORK, operator/control-VM — NEVER deploy/CI)
   grafana.com search  → deterministic ranked pick (datasource hard-filter → prefer_gnet → downloads → id-asc)
        │              → series-fit gate (the pinned board must query requires_series)
        ▼
   dashboards/derived/<method>.lock.yml     (id + revision + content_sha256 + datasource + requires_series + chosen_by)
   dashboards/grafana/dashboards/<name>.json   (the pinned board, same pin_datasource transform as fetch-dashboards.py)
        │
        ▼   scripts/gen-dashboard-floor.py --check   (OFFLINE, hermetic — BRICK-1; runs in tests/validate)
   asserts: schema:1 · every selector has a lock · board bytes hash to content_sha256 (the sha256 tamper floor) ·
            board still contains requires_series (offline re-grep) · lock matches its selector (no silent drift)
```

The board JSON is fetched by `scripts/fetch-dashboards.py` the same way a curated `{gnet, name}` block is — the
derived floor is a *normal* board once resolved. `--resolve` is the new **upstream** step that DERIVES *which* gnet a
method should carry; `fetch-dashboards.py` remains the download+provision verb for every board.

## The lock shape

```yaml
schema: 1
method: host_node                 # the telemetry method (== the lock filename stem)
name: node                        # the board filename stem → ../grafana/dashboards/node.json
id: 1860                          # grafana.com dashboard id — DERIVED by the ranked rule, never typed
revision: 45                      # the pinned (immutable) grafana.com revision
datasource: prometheus            # the datasource uid the board queries (must be a provisioned uid)
content_sha256: "sha256:<64hex>"  # over the pinned board bytes — the OFFLINE tamper floor
requires_series: node_cpu_seconds_total   # the series the board must query (the series-fit honesty gate)
chosen_by: prefer_gnet            # which tie-break rung selected it (prefer_gnet | downloads) — provenance
search: "node exporter full"      # the query it was resolved from — provenance
resolved_at: "2026-07-02"         # provenance ONLY; NOT read by --check (determinism, like facts.pinned probed_at)
```

## Operator: re-deriving

```
python3 scripts/gen-dashboard-floor.py --resolve [<method>]   # NETWORK; re-pins the lock(s) + board(s). Review the diff.
python3 scripts/gen-dashboard-floor.py --check                # OFFLINE; the install-gating coherence gate (validate/CI).
python3 scripts/gen-dashboard-floor.py --list                 # OFFLINE; prints the current pins.
```

Re-running `--resolve` freezes whatever the registry says *now*; any change (a new top board, a bumped revision)
surfaces as a `git diff` on the lock + the board JSON, reviewed like any other change. A **board swap** (a different
gnet than the existing pin) prints a LOUD stderr warning. This mirrors `gen-image-digests.py --refresh` bumping a
pinned digest and the L2b collection-tarball sha256 floor.

## Shared boards — the dual-owner note

A board file can have **two owners**: this derived floor (`gen-dashboard-floor.py`, pinning a specific revision) AND a
hand-listed curated `dashboards: [{gnet, name}]` block in some `module.yml` fetched by `fetch-dashboards.py` (which
pulls the **latest** revision). `node.json` (gnet 1860) is the live example — it is both the `host_node` derived floor
**and** proxmox's curated node board. Today they agree byte-for-byte (the derived lock pins the same board the curated
fetch would pull). If grafana.com later bumps gnet 1860 and an operator runs `fetch-dashboards.py` **without** also
re-running `gen-dashboard-floor.py --resolve`, the two owners diverge: `fetch-dashboards.py` rewrites `node.json` to
the newer bytes, and `--check` then fails **loudly** (`node.json sha256 != lock`) naming the method. **The derived lock
is authoritative** — re-run `--resolve` to re-pin (and review the resulting board diff). The `--check` error message
spells out this cause. (A future rung may make `fetch-dashboards.py` honor a derived lock's revision for shared gnets;
until then the offline `--check` is the guard.)

## See also

- [../README.md](../README.md) — the dashboard tiers (curated `{gnet,name}` vs this derived floor)
- [../../scripts/gen-dashboard-floor.py](../../scripts/gen-dashboard-floor.py) — the derive/check engine
- [../../scripts/fetch-dashboards.py](../../scripts/fetch-dashboards.py) — the download+provision verb
- [../../telemetry/host_node.yml](../../telemetry/host_node.yml) — a `derive_dashboard:` selector
- [../../docs/observability/hybrid-dashboard-discovery.md](../../docs/observability/hybrid-dashboard-discovery.md) — the sibling live-picker tier (`suggested_dashboards`, design-only) vs this pinned floor
