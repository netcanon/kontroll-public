"""Liveness route — GET /health. Cheap and unauthenticated; lets a check probe (and kontroll's
own OpenAPI ingester) confirm the service is up."""
from fastapi import APIRouter

from api.models import HealthResponse

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
def health() -> HealthResponse:
    """Return a static OK — the service is up. No auth, no I/O."""
    return HealthResponse(status="ok", service="kontroll-api")
