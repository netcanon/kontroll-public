"""Service layer — one drop-in module per onboarding domain.

Each module exposes pure-ish functions that COMPUTE and RETURN structured data (the
CLI's cmd_* wrappers in scripts/galaxy.py format the return value; the planned FastAPI
routes will call the same functions directly — docs/api-architecture.md §2). Read
operations are side-effect-free; mutators (onboard apply, capture-exception add,
scaffold, refresh) perform the repo/cache write and return what changed. The
commit/push gate stays in the CLI wrapper (the capture-exception exemplar's boundary).

Adding a domain operation = add a file here (never edit a hub) — the same drop-in
doctrine as inventory hosts, vectors, backends, and the capture-exception matrix.
"""
