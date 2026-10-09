"""Shared dependencies.

The capability **catalog** — the read-only drop-in registries (vectors/overrides/backends) — is
loaded once at startup (`load_catalog`, called from the lifespan) and injected into routes via
`get_catalog`. The per-request I/O (deep_probe / local_installed / galaxy_search) is NOT cached
here; it stays in the service functions, where tests patch it in the home modules.
"""
from dataclasses import dataclass

from fastapi import Request

from kontroll import catalog


@dataclass
class Catalog:
    """The loaded drop-in registries shared (read-only) across requests."""
    vectors: list
    overrides: dict
    backends: list
    capabilities: list


def load_catalog() -> Catalog:
    """Load vectors/overrides/backends/capabilities from the real tree — called once at app startup. The
    capability registry (capabilities/<cap>.yml) drives the generalized secondary-capability route, mirroring
    the other drop-in registries (adding a capability is a file drop, not a deps edit)."""
    return Catalog(vectors=catalog.load_vectors(),
                   overrides=catalog.load_overrides(),
                   backends=catalog.load_backends(),
                   capabilities=catalog.load_capabilities())


def get_catalog(request: Request) -> Catalog:
    """FastAPI dependency: the catalog loaded into `app.state` at startup."""
    return request.app.state.catalog
