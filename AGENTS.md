# kontroll — Agent & Contributor Directives

This repository uses **[CLAUDE.md](CLAUDE.md)** as the canonical, loaded-every-session
contributor-directives file. `AGENTS.md` exists so **tool-agnostic** agents and contributors
(any AI assistant, any human, any CI bot) find the rulebook under the emerging cross-tool
convention name — the rules are identical regardless of which kind of contributor authored a
change.

**Read [CLAUDE.md](CLAUDE.md) first.** It holds the core doctrine, the Hard Rules (Never Break),
the Documentation Sync Checklist, and the Before-you-commit checklist.

Deeper standards it points at:
- [docs/engineering-standards.md](docs/engineering-standards.md) — binding rationale (testing pyramid, logging, modularity)
- [docs/testing-standards.md](docs/testing-standards.md) — tests, test-docs, the data-testid SOP, the test-after-change loop, logging discipline
- [docs/qa-and-release-pipeline.md](docs/qa-and-release-pipeline.md) — CI, security scanning, build + dissemination
- [docs/agent-workflow.md](docs/agent-workflow.md) — the read-only-agent → main-thread-actuates protocol
- [tests/README.md](tests/README.md) — test-suite layout and how to run it
