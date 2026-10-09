"""kontroll onboarding API — a typed FastAPI over the `scripts/kontroll/` service package.

Workstream 2 of docs/api-architecture.md: read-only inquiry routes (search/probe/classify) that
call the service functions DIRECTLY (no subprocess-scrape — the GUI's current wart). The package
lives at the repo root alongside `gui/`; it imports the service layer from `scripts/kontroll/`, so
it puts `scripts/` on `sys.path` here (the same resolution the GUI + tests use) — done once at
package import, before any `from kontroll …` runs.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS = os.path.join(_ROOT, "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)
