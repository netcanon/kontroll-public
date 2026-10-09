"""Probe route — GET /probe/{collection}. Deep-probe one installed collection into its record."""
from fastapi import APIRouter, Depends, HTTPException

from api.deps import Catalog, get_catalog
from api.models import ProbeResponse
from kontroll.service.probe import service_probe

router = APIRouter(tags=["inquiry"])


@router.get("/probe/{collection}", response_model=ProbeResponse, summary="Deep-probe a collection")
def probe(collection: str, cat: Catalog = Depends(get_catalog)) -> dict:
    """Deep-probe `collection` (e.g. `cisco.ios`) and return its record + the raw module/plugin
    facts; 404 if the collection isn't installed locally."""
    result = service_probe(collection, vectors=cat.vectors, overrides=cat.overrides, backends=cat.backends)
    if result is None:
        raise HTTPException(status_code=404, detail="'%s' not installed locally" % collection)
    return {"record": result["record"], "modules": result["facts"]["modules"],
            "plugins": result["facts"]["plugins"]}
