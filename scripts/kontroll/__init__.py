"""kontroll service package — the capability/onboarding domain, extracted from the
galaxy.py CLI so every surface (CLI, the planned API, tests) calls one service layer.

Layout (docs/api-architecture.md §1):
  paths      — repo paths + shared constants (ROOT is the single repoint seam)
  predicate  — three-valued capability engine (eval_pred/eval_vector/classify)
  probe      — collection -> facts (shallow from Galaxy, deep from ansible-doc)
  catalog    — drop-in loaders + the local/Galaxy content sources
  record     — facts -> the result RECORD schema (+ overrides merge)
  gitio      — repo-mutation primitives (_run / _write_new / sops_set)
  service/   — one drop-in module per CLI domain; each returns structured data

The CLI (scripts/galaxy.py) is a thin formatter over this package and re-exports the
package's public functions, so existing call-style imports (galaxy.classify, …) keep
working; only the monkeypatch SEAMS move to their real home modules.
"""
