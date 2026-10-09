"""Search route — GET /search. The unified Galaxy + local capability search over the service layer."""
from fastapi import APIRouter, Depends, Query

from api.deps import Catalog, get_catalog
from api.models import Origin, Record
from kontroll.service.search import service_search

router = APIRouter(tags=["inquiry"])


@router.get("/search", response_model=list[Record], summary="Capability search (Galaxy + local)")
def search(
    q: list[str] = Query(..., description="keyword(s); repeat for multiple, e.g. ?q=cisco&q=ios"),
    origin: Origin = Query(Origin.both, description="search local, galaxy, or both"),
    limit: int = Query(8, ge=1, le=100, description="max Galaxy results"),
    vector: list[str] = Query(default=[], description="keep only results that HAVE these capabilities"),
    deep: bool = Query(False, description="deep-probe local matches (slower; resolves 'maybe' cells). "
                                          "Implied by a vector filter. Default: fast shallow records."),
    cat: Catalog = Depends(get_catalog),
) -> list:
    """Return the capability records matching the keyword(s), filtered to those that HAVE every requested
    `vector`, sorted local-first. Local hits are SHALLOW by default (fast — cells needing the deep doc
    parse read as 'maybe', resolvable via GET /probe/{collection}); `deep=true` (or any `vector`) re-probes
    the matched candidates deeply. Read-only; the catalog is injected (loaded once)."""
    return service_search(q, origin=origin.value, limit=limit, vector=vector, deep=deep,
                          vectors=cat.vectors, overrides=cat.overrides, backends=cat.backends)
