"""Units route — GET /units/{collection} + POST /units/{key}/configure + POST /units/preview. Enumerate a
collection's runnable units, validate an actuation unit's curated configure values, and preview what it would run.

The app-store "search → unit" seam (R1): a search result is a COLLECTION; GET projects it into the launchable
units the later configure/push stages act on. The configure seam (R3): POST /units/{key}/configure re-validates
the submitted knob values against the actuation unit's curated descriptor. The Review seam (R4): POST
/units/preview renders the would-run play + resolved vars + the --check-first hand-off. All three are WRITE-FREE
(a POST may take a body but stages nothing; design 24 §4); the SEC-3 traversal guard lives in the service layer
(`service_units` resolves `collection` against the enumerated installed set, never a raw path-join).
"""
from fastapi import APIRouter, HTTPException

from api.models import ConfigureRequest, ConfigureResponse, PreviewRequest, PreviewResponse, UnitsResponse
from kontroll.service.actuation import build_actuation_plan
from kontroll.service.units import service_units, validate_unit_config

router = APIRouter(tags=["inquiry"])


@router.get("/units/{collection}", response_model=UnitsResponse, summary="List a collection's runnable units")
def units(collection: str) -> dict:
    """Enumerate the runnable units (collection-shipped playbooks + roles) of `collection` (e.g. `cisco.ios`);
    404 if it isn't installed locally. A collection that ships only modules returns an empty `units` list."""
    result = service_units(collection)
    if result is None:
        raise HTTPException(status_code=404, detail="'%s' not installed locally" % collection)
    return result


@router.post("/units/{key}/configure", response_model=ConfigureResponse,
             summary="Validate an actuation unit's configure values")
def configure(key: str, body: ConfigureRequest) -> dict:
    """Re-validate the submitted configure `values` against actuation unit `key`'s curated knob descriptors
    (R3 configure form) — the server-side gate the GUI's Configure stage calls before advancing. 404 if no unit
    with that key exists. WRITE-FREE: it validates and returns `{ok, errors}`; it stages nothing, decrypts
    nothing (design 24 §4 read-POST)."""
    result = validate_unit_config(key, body.values)
    if result.get("error") == "no_unit":
        raise HTTPException(status_code=404, detail="no actuation unit '%s'" % key)
    return {"key": key, "ok": result["ok"], "errors": result["errors"]}


@router.post("/units/preview", response_model=PreviewResponse, summary="Preview an actuation unit's would-run play")
def preview(body: PreviewRequest) -> dict:
    """Render what actuation unit `body.key` WOULD run with the submitted `values` — the write-free Review stage
    (R4, design 24 §5): the would-run play (the role wrapper / the FQCN run-spec, with the derived access-chain
    header), the resolved non-secret vars, the `--check`-first hand-off, and the post-promote enact steps. 404 if
    no such unit; 422 if the values don't validate. WRITE-FREE — it renders and returns; it stages nothing."""
    plan = build_actuation_plan(body.key, body.values)
    if plan.get("error") == "no_unit":
        raise HTTPException(status_code=404, detail="no actuation unit '%s'" % body.key)
    if plan.get("error") == "invalid":
        raise HTTPException(status_code=422, detail={"errors": plan["errors"]})
    return plan
