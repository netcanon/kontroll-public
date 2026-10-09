# Contributing to kontroll

Thanks for considering a contribution. kontroll has an opinionated shape — what gets
accepted, what doesn't, and why — that is worth reading before you write code.

## What this project values

kontroll is a **composed control plane for a homelab**: Semaphore (Ansible UI), Homepage,
Prometheus + Grafana, Loki + Vector and SOPS + age, driven by a device-class **module
registry** and a **two-key propose → promote** spine. Three disciplines govern every change:

- **Deeply modular, no god files.** Adding a device class, a telemetry/logging method, a
  dashboard or a metrics target means *creating a new file*, never editing a hub file
  (PLAN.md §2.5, the "add an X" test).
- **Config-as-data, generated, validated.** Collections, Prometheus targets, exporter
  fragments and dashboards are *generated* from the module registry + inventory and kept
  honest by `--check` gates in `tests/validate.sh`. Nothing bespoke; a hand edit to a
  generated file fails CI.
- **Tests, test-docs and logging are first-class deliverables.** A behaviour change is not
  done until the test that proves it, its docstring (*what it verifies and why*), and its
  `kontroll_run_id`-correlated log line land in the same commit
  ([docs/testing-standards.md](docs/testing-standards.md)).

The rulebook is [CLAUDE.md](CLAUDE.md) (also reachable as [AGENTS.md](AGENTS.md) for
tool-agnostic agents). Its **Hard Rules** and **Documentation Sync Checklist** apply to every
contributor — human, AI, or mixed.

## Your lab stays yours — and out of the repo

Everything that identifies a real deployment lives in a private `instance/` overlay
(template: [`instance.example/`](instance.example/README.md)) and never in the tool: no
RFC-1918 address, MAC, hostname, domain, serial or operator-machine path belongs in a
tracked file. Use the documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`,
`00:00:5e:00:53:xx`, `example.com`) in docs, fixtures and examples. The gate is
`tests/_leak_guard.py` (run by `tests/validate.sh` and the PII-guard workflow); a line that
*must* hold a private address carries a `pii-guard: allow <reason>` marker so the exception
is visible in review.

## Three contribution paths

### 1. Add a device class (a module)

Create `modules/<key>/module.yml` describing the class (collection, inventory group,
secrets domain, telemetry/logging/backup blocks) and the matching `ansible/roles/<key>/`
with a `backup` entrypoint and an access-chain header. Run `tests/validate.sh`; the
generators regenerate everything else. See [modules/README.md](modules/README.md).

### 2. Add a telemetry, logging or discovery method

Drop a `telemetry/<method>.yml`, `logging/<method>.yml` or `discovery/<method>.yml`
descriptor. The registries are data; the generators and the GUI pick the file up. Vendor
specifics stay in the descriptor, never in a playbook branch (the one dispatch seam is
`device_role`).

### 3. Fix or improve the docs

Stale docs are a bug. Every row of the Documentation Sync Checklist exists because someone
shipped drift by forgetting it — if your change renders a doc stale, fix the doc in the same
commit.

## The development loop

```bash
pip install -r tests/requirements-dev.txt
bash tests/validate.sh            # the one gate: lint · secrets · compose · generators · pytest · pii-guard
pytest -m "not e2e and not slow"  # the hermetic suite on its own
```

CI (`.github/workflows/ci.yml`) runs the **same** `tests/validate.sh --strict`, the pytest
matrix (3.11–3.14), the snmp-generator byte-gate and the Playwright e2e suite on every pull
request; the PII guard runs alongside. `main` is protected: changes land by pull request with
every check green.

## Commits and pull requests

- Conventional Commits, scope = component (`ansible`, `docker`, `dashboards`, `prometheus`,
  `docs`, `repo`, `gui`, `api`). One logical theme per commit.
- **Rationale-first bodies**: open with *why*; the diff already shows the *what*.
- Behaviour-affecting changes get a `CHANGELOG.md [Unreleased]` entry.
- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin 1.1](https://developercertificate.org/).
- Fill in the pull-request template; the doc-sync checklist is the most-skipped reviewer
  concern.

## Security

Never open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md) for the
private reporting channel and the threat model.
