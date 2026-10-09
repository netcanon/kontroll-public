# overrides — capability-matrix corrections (drop-in)

The prober derives capability labels from a collection's structure (`ansible-doc -j`
+ Galaxy contents). That's honest but incomplete: some devices back up via a
vendor API the standard signals don't see (FortiGate), and `backup_capable` is
sometimes a *judgment* (technically possible ≠ meaningful). Those corrections live
here — one file per collection, applied on top of the derived record.

An override never edits generated data; `galaxy.py` merges it at read time and
marks the affected capabilities `provenance: override` (shown with `*`).

## Format

```yaml
collection: fortinet.fortios          # the collection an entry is keyed by
capabilities:                         # patch one or more vectors (by vector name)
  backup:
    state: yes                        # yes | no | maybe
    confidence: high
    evidence: "REST monitor config-backup API (api backend)"
note: "Why this override exists — shown in search output."
```

These files are committed (they're curated knowledge). An AI agent can maintain
them via the agent-workflow; that's the lightweight alternative to an external
matrix repo (see docs/capability-matrix.md §3.1).

## Sibling pattern

This corrects capability *classification*. The same sparse, member-only, drop-in idea is
applied to capture *behaviour* by [../config/capture-exceptions.yml](../config/capture-exceptions.yml)
— a registry of only the captures that misbehave (e.g. FortiGate's non-deterministic
full-config export), consumed by `backup-configs.yml` at backup time. Same DNA, different seam.

## See also
- [../docs/capability-matrix.md](../docs/capability-matrix.md) — design
- [../vectors/](../vectors/) — what `capabilities` keys are available
- [../scripts/galaxy.py](../scripts/galaxy.py) — applies these
- [../config/capture-exceptions.yml](../config/capture-exceptions.yml) — the capture-behaviour sibling
