# Distributed agent work — how we run reviews & audits

Replicated from the **netcanon** project's methodology (security-triage /
docs-audit sister-processes), adapted to this IaC control-plane repo. This is the
binding process for any multi-agent review, audit, or research task here.

The one-line shape:

> **snapshot → cluster scope files → parallel read-only agents → orchestrator
> synthesis → fix-plan → main-thread actuation → evidence-trail commit**

## The load-bearing rule: read-only agents, main thread actuates

- **Stage-1 agents are strictly read-only on the repo and the lab.** An agent may
  read anything; it may **write ONLY its one designated report file** under the
  run folder. No source edits, no `git add`/commit, no `ansible-playbook`, no
  touching the live fleet. No worktree isolation is needed precisely *because*
  they cannot edit (saves disk + dispatch cost).
- **The orchestrator (main thread) is the only actor that validates and
  actuates.** It reads the agents' reports, reconciles them into a synthesis +
  fix-plan, and then applies fixes, commits, and runs anything against the lab —
  itself, or by dispatching **Stage-2 implementation agents** *only* where the
  fix scope genuinely warrants it (and those use worktree isolation if they edit
  shared files in parallel).

This is the same split as our existing discipline (`PLAN.md` access-chain rule):
research fans out cheaply and safely; mutation is centralized and verified.

## Ultracode runs — the Workflow-tool blackboard (the consistent mechanism)

Ultracode runs (the `ultracode` keyword opts a turn into multi-agent orchestration) operationalize the process
above through the **`Workflow` tool** + the reusable runner
[../.claude/workflows/blackboard.js](../.claude/workflows/blackboard.js) (invoked by **`scriptPath`** —
`Workflow({ scriptPath: "<repo>/.claude/workflows/blackboard.js", args })`; the `name:` registry is reserved
for built-in/plugin workflows). **This runner is the only sanctioned shape** — it bakes the
load-bearing rule in (read-only agents, one report file each, main thread actuates) so the discipline can't be
re-hand-rolled or drift. The `args` contract + invocation recipe live in
[../.claude/workflows/README.md](../.claude/workflows/README.md); this section is the convention it implements.

**Run folder** = `docs/reviews/<UTC-date>-<slug>/` (the topical `-<slug>` distinguishes a research+design run
from a whole-repo audit, which may drop the slug — same family, phase-appropriate file names):

```
docs/reviews/<UTC-date>-<slug>/
  00-blackboard.md            # SEED — the MAIN THREAD writes this BEFORE the run: mission, hard constraints, roster
  10-research-<x>.md          # Stage-1 research agents (10s) — each its ONLY write
  11-research-<y>.md
  20-design-<a>.md            # Stage-1 design agents (20s) — read the 10s for peer comms
  21-design-<b>.md
  30-review-adversarial.md    # adversarial review (30s) — reads all 10s + 20s
  99-synthesis.md             # SYNTHESIS — the MAIN THREAD writes this AFTER: reconciled decisions + buildable-now
```

- **Numeric prefixes encode phase order** (10s research → 20s design → 30s review); the prefix is the agent's
  `id` *and* its report filename. Phases run as `parallel()` barriers; later phases read earlier reports for comms.
- **The runner has NO filesystem access** — it only orchestrates agents. So the **main thread owns the
  bookends**: write `00-blackboard.md` (the seed) before invoking, `99-synthesis.md` after, and then build /
  validate / commit — the sole actuator. Agents write only their one `NN-*.md`.
- **Agents return only a pointer/summary**; the long-form analysis lives in the file (keeps the main thread
  light). Reviewers return a verdict + severity-tagged must-fixes.
- **Opus for every agent** (the runner's default) — long-context retention + design/audit quality (CLAUDE.md:
  never under-model a design/audit/research agent).

### The `00-blackboard.md` seed template (the main thread fills + writes this before invoking)

```markdown
# Blackboard — <mission title> (<UTC-date>)

**Process:** netcanon file-per-agent blackboard. Read-only agents each write EXACTLY ONE report in this dir; the
main thread seeds this file + writes 99-synthesis.md + is the sole actor that builds/commits.

## Mission
<what this run examines/decides — 1-3 bullets>

## Hard constraints (apply to every report)
<the non-negotiables for THIS run — e.g. homelab scale / no over-engineering; no god files / drop-ins /
zero-spine-edit; INVARIANT-D; C8/C12 at-rest; fail-closed knobs>

## File roster
| File | Phase | Author | Covers |
|---|---|---|---|
| 00-blackboard.md | seed | main thread | this protocol + mission + constraints |
| 10-research-<x>.md | research | R1 | ... |
| 30-review-adversarial.md | review | V1 | GO/NO-GO + must-fixes |
| 99-synthesis.md | synthesis | main thread | reconciled decisions + buildable-now contract |

## Decisions already locked (context)
<prior decisions the agents should treat as fixed>
```

## Directory structure (the evidence trail)

Every run gets a **dated evidence folder**, frozen and reproducible:

```
docs/reviews/<UTC-DATE>/
  00-snapshot.md            # repo/state inventory at the start of the run
  cluster-<X>-scope.md      # the focused input handed to agent X
  01-investigation-<X>.md   # agent X's report (its ONLY write) — a verdict table
  99-synthesis.md           # orchestrator: consolidated findings (CONFIRMED / DISMISSED)
  fix-plan.md               # orchestrator: fixes grouped by file/theme
```

Conventions:
- Folder name = **UTC date** of the snapshot (matches commit/GitHub timestamps).
- Numeric prefixes encode pipeline order: `00-` snapshot, `01-` Stage-1 outputs,
  `99-` synthesis.
- These folders are **EXPECTED-STALE**: a later audit must never flag a past
  run's evidence as drift. They are a frozen record, not live docs.
- Agents hand off purely via their `01-investigation-<X>.md`; the orchestrator
  reconciles in `99-synthesis.md`.

## Agent report format (verdict table)

Each Stage-1 agent's report is a table so the orchestrator can reconcile fast:

```
| # | Path:Line | Severity | Finding | Verdict (CONFIRMED/DISMISSED) | Fix shape |
```

Severity tags for a scaffolding/docs review: **WRONG / MISSING / INCOMPLETE /
STYLE / EXPECTED-STALE** (the last = a deliberate pattern, not a defect).

## Cluster taxonomy (how work is scoped & parallelized)

Group findings by the **kind of investigation** they need, not by file type — that
is what makes it parallelizable. Labels are **stable across runs** so future
searches find prior investigations under the same name. Each agent owns a
**non-overlapping scope**. Standard clusters for a kontroll scaffolding review:

| Cluster | Owns |
|---|---|
| **A — Interlinking & structure** | every internal markdown link resolves; required README sections present; "See also" reciprocity |
| **B — Testing & contracts** | test pyramid coverage; single dispatch seam (`device_role`/`mock-inventory`); idempotence; module→role→group→secrets contract complete |
| **C — Docs accuracy** | every state-claim matches reality; SECURITY control→file→covering-check; no hard-coded counts in prose; CHANGELOG current |
| **D — Logging & secrets & hard rules** | `no_log` on every secret-handling task; nothing unencrypted/committed; CLAUDE.md hard rules actually upheld in code |
| **E — Modularity / altitude** | no god files; additive growth; generated-vs-hand-maintained correct; "add an X" recipes accurate |

## Dispatch heuristics

- **Model:** Opus for the read-only investigation agents (long-context retention
  across many files); the orchestrator runs on the main thread.
- **Parallelism:** one agent per cluster, dispatched together. More agents ≠
  faster when each cluster is file-bounded — and harder to reconcile.
- **File-overlap check before dispatch:** if two agents would need to *edit* the
  same file (Stage 2), serialize them or split the file. Stage-1 is read-only so
  overlap is harmless.
- **Keep findings in files, not the main thread.** Agents write full detail to
  their report file and return only a short summary + the path, so the main
  thread's context stays light (this is the whole point of off-thread research).

## When to invoke vs. inline

- **Invoke the full process** on a *wave*: a scaffolding/doc audit, a pre-release
  gate, a post-large-change sweep, or a periodic cadence.
- **For a one-off** finding or small doc fix, just fix it inline — don't spin up
  the process.

## Stage 2 (actuation)

The orchestrator executes fixes **commit-by-commit, one logical theme per
commit**, with rationale-first commit messages (see commit conventions in
[CLAUDE.md](../CLAUDE.md)). It re-runs `tests/validate` (and live checks where relevant) after
each theme. Stage-2 agents are spawned only for genuinely multi-file fixes.

## See also
- [../CLAUDE.md](../CLAUDE.md) — hard rules + the Documentation Sync Checklist
- [engineering-standards.md](engineering-standards.md) — testing/docs/logging doctrine
- [../PLAN.md](../PLAN.md) §2.5 — the modularity doctrine the audits enforce
