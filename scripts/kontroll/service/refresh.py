"""refresh domain — rebuild the capability-matrix cache for every installed collection.

service_refresh deep-probes every installed collection, writes the derived records to
the (gitignored) cache, and returns {"count","path","records"}; the CLI prints the
one-line summary.
"""
import json

from kontroll import catalog, paths, probe, record


def service_refresh(vectors=None, overrides=None, backends=None):
    """Deep-probe every locally-installed collection, write the derived records to the
    capability-matrix cache, and return {"count","path","records"}."""
    vectors = vectors if vectors is not None else catalog.load_vectors()
    overrides = overrides if overrides is not None else catalog.load_overrides()
    backends = backends if backends is not None else catalog.load_backends()
    records = [record.build_record(probe.deep_probe(coll, ver), vectors, overrides, backends)
               for coll, ver in sorted(catalog.local_installed().items())]
    with open(paths.MATRIX_CACHE, "w", encoding="utf-8") as fh:
        json.dump({"records": records}, fh, indent=2)
    return {"count": len(records), "path": paths.MATRIX_CACHE, "records": records}
