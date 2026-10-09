"""Capture-exception route — POST /capture-exceptions. Declare a capture-exception in the sparse
matrix and commit + push the LOCAL canonical (privileged, audited) — the API form of
`galaxy.py capture-exception add --commit`.
"""
import os
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator

from api.auth import Principal, audit_action, require_token
from kontroll import gitio
from kontroll.service.capture_exception import add_capture_exception

router = APIRouter(tags=["privileged"])

_MATCH_RE = re.compile(r"[A-Za-z0-9_.*?\[\]\-]+")


class CaptureExceptionIn(BaseModel):
    """The body of a capture-exception declaration. `match` is constrained to a capture-filename
    glob (it flows into a rendered .gitignore + `git rm` pathspecs downstream — a bad value would
    corrupt them), validated here so a bad request is a clean 422, not a service sys.exit."""
    subject: str
    match: str
    behavior: str = "non_deterministic"
    disposition: str = "exclude_from_history"
    observed: str = ""
    source: str = "user"
    push: bool = False                 # also push origin (optional offsite backup)

    @field_validator("match")
    @classmethod
    def _valid_match(cls, v: str) -> str:
        if not _MATCH_RE.fullmatch(v):
            raise ValueError("must be a capture-filename glob (letters/digits and . _ - * ? [ ])")
        return v


@router.post("/capture-exceptions", summary="Declare a capture-exception (audited)")
def add_exception(body: CaptureExceptionIn, request: Request,
                  principal: Principal = Depends(require_token)) -> dict:
    """Add a member to the capture-exception matrix and commit + push the LOCAL canonical. Privileged
    (token + audit). The matrix write is adversarial-safe (yaml.safe_dump) and idempotent (same match
    ⇒ no-op, no commit). Returns what changed + the run_id; a failed commit never pushes a stale HEAD."""
    audit_action(request, principal, "capture-exception",
                 "match=%s subject=%s" % (body.match, body.subject))
    try:
        added = add_capture_exception(body.subject, body.match, body.behavior,
                                      body.disposition, body.observed, body.source)
    except SystemExit as e:            # the service sys.exits on a corrupt / no-`exceptions:`-key file
        raise HTTPException(status_code=400, detail=str(e)) from e
    if not added:
        return {"added": False, "committed": False, "run_id": principal.run_id}
    git = gitio.commit_and_push(
        [os.path.join("config", "capture-exceptions.yml")],
        ["feat(logging): capture-exception += %s" % body.match,
         "Added via the kontroll API (run_id %s; subject %s)." % (principal.run_id, body.subject),
         "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"],
        push_origin=body.push, run_id=principal.run_id)   # staging network service ⇒ proposed/<run_id> (C10)
    if not git["committed"]:           # never push a stale HEAD on a failed commit
        raise HTTPException(status_code=500, detail="commit failed; nothing pushed")
    return {"added": True, "committed": True, "pushed_canonical": git["pushed_canonical"],
            "pushed_origin": git["pushed_origin"], "target_ref": git["target_ref"],
            "staged": git["staged"], "run_id": principal.run_id}
