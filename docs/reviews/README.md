# docs/reviews/ — design and review dossiers

Multi-agent reviews, audits and design runs write their reports here, one folder per run
(`<UTC-date>-<slug>/`), following [docs/agent-workflow.md](../agent-workflow.md): read-only
agents each write one report, the main thread writes the `00-blackboard.md` seed and the
`99-synthesis.md` reconciliation, and only the main thread acts on the result.

**Where the pre-release dossiers are.** Everything dated before the public release
(2026-10-08) was produced against the maintainer's private instance and quotes its real
topology, so those folders live only in the private development repository. Links into
them from `CHANGELOG.md` and the design docs are kept for provenance and will not resolve
here. Dossiers written after the release are published in this directory and must pass
the same identifier-leak gate as every other tracked file (`tests/_leak_guard.py`, run by
`tests/validate.sh` and the PII-guard workflow) — a report may quote example data, never a
real address or hostname.
