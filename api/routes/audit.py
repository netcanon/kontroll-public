"""Audit-log query route — GET /audit/log. A privileged READ over the same TSV the mutations write."""
from typing import Optional

from fastapi import APIRouter, Depends, Request

from api.audit import read_audit
from api.auth import Principal, require_token

router = APIRouter(tags=["privileged"])


@router.get("/audit/log", summary="Query the audit log")
def query_audit(request: Request,
                principal: Principal = Depends(require_token),
                action: Optional[str] = None, user: Optional[str] = None,
                run_id: Optional[str] = None, since: Optional[str] = None,
                limit: int = 200) -> dict:
    """Return recent audit lines (most recent first), optionally filtered by action/user/run_id and a
    `since` ISO-timestamp. Privileged read (token); it does NOT itself write an audit line. Makes the
    cross-silo 'show me everything for this run_id' query possible (docs/logging-architecture.md §7)."""
    settings = request.app.state.settings
    rows = read_audit(settings.audit_log, action=action, user=user,
                      run_id=run_id, since=since, limit=limit)
    return {"count": len(rows), "rows": rows}
