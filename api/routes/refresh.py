"""Refresh route — POST /refresh. Rebuild the capability-matrix cache (privileged, audited)."""
from fastapi import APIRouter, Depends, Request

from api.auth import Principal, audit_action, require_token
from api.deps import Catalog, get_catalog
from kontroll.service.refresh import service_refresh

router = APIRouter(tags=["privileged"])


@router.post("/refresh", summary="Rebuild the capability-matrix cache")
def refresh(request: Request,
            principal: Principal = Depends(require_token),
            cat: Catalog = Depends(get_catalog)) -> dict:
    """Deep-probe every installed collection and rebuild the (gitignored) capability-matrix cache.
    Privileged (token + audit); writes only the cache — no git, no lab. Returns {count, run_id}.
    The lowest-blast-radius privileged route — the one that proves the auth/audit machinery."""
    audit_action(request, principal, "refresh")
    result = service_refresh(vectors=cat.vectors, overrides=cat.overrides, backends=cat.backends)
    return {"count": result["count"], "run_id": principal.run_id}
